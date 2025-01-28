package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/micahhausler/aws-iam-policy/policy"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"

	godiff "codeberg.org/h7c/go-diff"

	"github.com/agnivade/levenshtein"
)

const (
	levenshteinFactor = 100
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func fetchAllPolicies(svc *iam.Client, roleName string) ([]string, error) {
	var allPolicies []string

	inlinePolicies, err := svc.ListRolePolicies(context.TODO(), &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	check(err)
	for _, policyName := range inlinePolicies.PolicyNames {
		fmt.Println("Reading inline policy", policyName, "for Role", roleName)
		inlinePolicyDocs, err := svc.GetRolePolicy(context.TODO(), &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		check(err)
		decodedPol, _ := url.QueryUnescape(*inlinePolicyDocs.PolicyDocument)
		// fmt.Printf("%s\n", decodedPol)
		allPolicies = append(allPolicies, decodedPol)
	}

	attachedPolicies, err := svc.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	check(err)
	for _, attachedPolicy := range attachedPolicies.AttachedPolicies {
		fmt.Println("Reading attached policy", *attachedPolicy.PolicyName, "for Role", roleName)
		policyDetails, err := svc.GetPolicy(context.TODO(), &iam.GetPolicyInput{
			PolicyArn: attachedPolicy.PolicyArn,
		})
		check(err)
		attachedPolicyDocs, err := svc.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
			PolicyArn: attachedPolicy.PolicyArn,
			VersionId: policyDetails.Policy.DefaultVersionId,
		})
		check(err)
		decodedPol, _ := url.QueryUnescape(*attachedPolicyDocs.PolicyVersion.Document)
		// fmt.Printf("%s\n", decodedPol)
		allPolicies = append(allPolicies, decodedPol)
	}
	return allPolicies, nil
}

func fetchLocalPolicies(globexpr string) []string {
	var combinedPolicies []string

	matches, _ := filepath.Glob(globexpr)
	for _, match := range matches {
		dat, err := os.ReadFile(match)
		check(err)
		combinedPolicies = append(combinedPolicies, string(dat))
	}
	return combinedPolicies
}

func buildCombinedPolicy(docs []string) policy.Policy {
	combinedStatements := policy.NewStatementOrSlice()

	for _, doc := range docs {
		// fmt.Print(string(dat))
		pol := policy.Policy{}
		json.Unmarshal([]byte(doc), &pol)
		//fmt.Printf("%v+\n", pol)
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

func comparePolicies(policyA, policyB policy.Policy) {
	lenA := len(policyA.Statements.Values())
	lenB := len(policyB.Statements.Values())

	maxStatementCount := lenA
	// minStatementCount := lenB

	if lenA < lenB {
		maxStatementCount = lenB
		// minStatementCount = lenA
	}

	indexA := 0
	indexB := 0

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
			// fmt.Println("The distance between the statements is ", distance)

			awsServiceA := strings.Split(policyA.Statements.Values()[indexA].Resource.Values()[0], ":")[2]
			awsServiceB := strings.Split(policyB.Statements.Values()[indexA].Resource.Values()[0], ":")[2]
			// fmt.Println("Service A: ", awsServiceA, ", Service B:", awsServiceB)

			if distance < levenshteinFactor && awsServiceA == awsServiceB {
				// fmt.Println("Similar enough, adding both")
				fmt.Printf("[AWS Service: %s]\n", awsServiceA)
				printDiff(statementA, statementB)
			} else {
				if indexA < indexB {
					// fmt.Println("Add only A")
					fmt.Printf("[AWS Service: %s]\n", awsServiceA)
					printDiff(statementA, []byte(""))
					addB = false
				} else {
					// fmt.Println("Add only B")
					fmt.Printf("[AWS Service: %s]\n", awsServiceB)
					printDiff([]byte(""), statementB)
					addA = false
				}
			}
		}

		// fmt.Println("addA: ", addA, " addB: ", addB)

		if !addA && !addB {
			continue
		}
		if addA {
			indexA++
		}
		if addB {
			indexB++
		}

		// fmt.Println("A", indexA)
		// fmt.Println("B", indexB)
	}
}

func printDiff(old, new []byte) {

	f1 := godiff.NewFileFromBytes(old)
	f2 := godiff.NewFileFromBytes(new)

	if f1.IsDifferentFrom(f2) {
		godiff.ShowDiff(f1, f2, true)
	}
}

func main() {
	fmt.Println("IAM Role comparison")

	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("us-west-2"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	oldRole := os.Args[1]
	newRole := os.Args[2]

	if oldRole == "" || newRole == "" {
		fmt.Println("Please provide role names")
		os.Exit(1)
	}

	fmt.Println("Comparing", oldRole, "and", newRole)

	svc := iam.NewFromConfig(cfg)

	originalPolicyDocs, err := fetchAllPolicies(svc, oldRole)
	check(err)

	newPolicyDocs, err := fetchAllPolicies(svc, newRole)
	check(err)

	// originalPolicyDocs := fetchLocalPolicies("fixtures/cdk/*")
	fmt.Println("Building a combined and sorted policy doc for", oldRole)
	originalPolicy := buildCombinedPolicy(originalPolicyDocs)

	// newPolicyDocs := fetchLocalPolicies("fixtures/terragrunt/*")
	fmt.Println("Building a combined and sorted policy doc for", newRole)
	newPolicy := buildCombinedPolicy(newPolicyDocs)

	comparePolicies(originalPolicy, newPolicy)

	// save policies for manual diff - still needed?
	outOriginalText, _ := json.MarshalIndent(originalPolicy, "", "\t")
	outNewText, _ := json.MarshalIndent(newPolicy, "", "\t")

	os.WriteFile("out/original.json", outOriginalText, 0644)
	os.WriteFile("out/new.json", outNewText, 0644)
}
