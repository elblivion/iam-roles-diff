package main

import (
	"fmt"
	"os"
)

func usage() {
	usage := `
Usage:
	iam-roles-diff <role_name-1> <role_name-2>

	`
	fmt.Println(usage)
}

func main() {
	fmt.Println("IAM Roles Differ")

	if len(os.Args) != 3 {
		usage()
		os.Exit(1)
	}

	originalRole := os.Args[1]
	newRole := os.Args[2]

	if originalRole == "" || newRole == "" {
		usage()
		os.Exit(1)
	}

	originalPolicyDocs, err := fetchAllPoliciesForRole(originalRole)
	if err != nil {
		panic(err)
	}

	newPolicyDocs, err := fetchAllPoliciesForRole(newRole)
	if err != nil {
		panic(err)
	}

	fmt.Println("Building a combined and sorted policy doc for", originalRole)
	original := &roleWithPolicies{
		RoleName:       originalRole,
		CombinedPolicy: buildCombinedPolicy(originalPolicyDocs),
	}

	fmt.Println("Building a combined and sorted policy doc for", newRole)
	new := &roleWithPolicies{
		RoleName:       newRole,
		CombinedPolicy: buildCombinedPolicy(newPolicyDocs),
	}

	comparePolicies(*original, *new)
}
