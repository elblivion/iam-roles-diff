package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	godiff "codeberg.org/h7c/go-diff"
	"github.com/agnivade/levenshtein"
	"github.com/micahhausler/aws-iam-policy/policy"
)

type roleWithPolicies struct {
	RoleName       string
	CombinedPolicy policy.Policy
}

const (
	defaultMaxLevenshteinDistance = 100
)

func maxLevenshteinDistance() int {
	fromEnvStr, present := os.LookupEnv("IAM_ROLE_DIFF_MAX_DISTANCE")
	if !present {
		return defaultMaxLevenshteinDistance
	}
	fromEnv, err := strconv.Atoi(fromEnvStr)
	if err != nil {
		log.Printf("IAM_ROLE_DIFF_MAX_DISTANCE %s was not a number", fromEnvStr)
		return defaultMaxLevenshteinDistance
	}
	return fromEnv
}

// Diff helper

func printDiff(original, new []byte) {
	f1 := godiff.NewFileFromBytes(original)
	f2 := godiff.NewFileFromBytes(new)

	if f1.IsDifferentFrom(f2) {
		godiff.ShowDiff(f1, f2, true)
	}
}

func buildCombinedPolicy(docs []string) policy.Policy {
	combinedStatements := policy.NewStatementOrSlice()

	for _, doc := range docs {
		pol := policy.Policy{}
		json.Unmarshal([]byte(doc), &pol)
		statements := pol.Statements.Values()

		for i := range statements {
			sort.Strings(statements[i].Action.Values())
			combinedStatements.Add(statements[i])
		}
	}

	slices.SortFunc(combinedStatements.Values(),
		func(a, b policy.Statement) int {
			aService := strings.Split(a.Action.Values()[0], ":")[0]
			bService := strings.Split(b.Action.Values()[0], ":")[0]

			return cmp.Compare(aService, bService)
		})

	return policy.Policy{
		Version:    policy.VersionLatest,
		Id:         "combined",
		Statements: combinedStatements,
	}
}

func comparePolicies(roleA, roleB roleWithPolicies) {
	maxDistance := maxLevenshteinDistance()

	fmt.Println()
	printDiff([]byte(roleA.RoleName), []byte(roleB.RoleName))
	fmt.Println()

	policyA := roleA.CombinedPolicy
	policyB := roleB.CombinedPolicy

	lenA := len(policyA.Statements.Values())
	lenB := len(policyB.Statements.Values())

	maxStatementCount := lenA

	if lenA < lenB {
		maxStatementCount = lenB
	}

	indexA := 0
	indexB := 0

	// use the two indices in for loop
	for i := 0; i < maxStatementCount; i++ {
		addA := true
		addB := true

		if indexA >= lenA {
			addA = false
		}

		if indexB >= lenB {
			addB = false
		}

		if addA && addB {
			statementA, _ := json.MarshalIndent(policyA.Statements.Values()[indexA], "", "\t")
			statementB, _ := json.MarshalIndent(policyB.Statements.Values()[indexB], "", "\t")
			distance := levenshtein.ComputeDistance(string(statementA), string(statementB))

			awsServiceA := strings.Split(policyA.Statements.Values()[indexA].Resource.Values()[0], ":")[2]
			awsServiceB := strings.Split(policyB.Statements.Values()[indexA].Resource.Values()[0], ":")[2]

			if distance < maxDistance && awsServiceA == awsServiceB {
				fmt.Printf("[AWS Service: %s]\n", awsServiceA)
				printDiff(statementA, statementB)
			} else {
				if indexA < indexB {
					fmt.Printf("[AWS Service: %s]\n", awsServiceA)
					printDiff(statementA, []byte(""))
					addB = false
				} else {
					fmt.Printf("[AWS Service: %s]\n", awsServiceB)
					printDiff([]byte(""), statementB)
					addA = false
				}
			}
		}

		if !addA && !addB {
			continue
		}
		if addA {
			indexA++
		}
		if addB {
			indexB++
		}
	}
}
