package main

import (
	"context"
	"fmt"
	"log"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

func fetchAllPoliciesForRole(roleName string) ([]string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-central-1"))
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}
	svc := iam.NewFromConfig(cfg)

	var allPolicies []string

	inlinePolicies, err := svc.ListRolePolicies(context.TODO(), &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		panic(err)
	}

	for _, policyName := range inlinePolicies.PolicyNames {
		fmt.Println("Reading inline policy", policyName, "for Role", roleName)

		inlinePolicyDocs, err := svc.GetRolePolicy(context.TODO(), &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			panic(err)
		}

		decodedPol, _ := url.QueryUnescape(*inlinePolicyDocs.PolicyDocument)
		allPolicies = append(allPolicies, decodedPol)
	}

	attachedPolicies, err := svc.ListAttachedRolePolicies(context.TODO(), &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		panic(err)
	}
	for _, attachedPolicy := range attachedPolicies.AttachedPolicies {
		fmt.Println("Reading attached policy", *attachedPolicy.PolicyName, "for Role", roleName)

		policyDetails, err := svc.GetPolicy(context.TODO(), &iam.GetPolicyInput{
			PolicyArn: attachedPolicy.PolicyArn,
		})
		if err != nil {
			panic(err)
		}

		attachedPolicyDocs, err := svc.GetPolicyVersion(context.TODO(), &iam.GetPolicyVersionInput{
			PolicyArn: attachedPolicy.PolicyArn,
			VersionId: policyDetails.Policy.DefaultVersionId,
		})
		if err != nil {
			panic(err)
		}

		decodedPol, _ := url.QueryUnescape(*attachedPolicyDocs.PolicyVersion.Document)
		allPolicies = append(allPolicies, decodedPol)
	}

	return allPolicies, nil
}
