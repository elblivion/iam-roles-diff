# iam-roles-diff

For a recent project we wanted to reprovision IAM Roles with a different IaC mechanism and 
check that the resulting role policies were reasonably similar. I couldn't find a tool for
this so I wrote one.

```
$ AWS_PROFILE=development iam-roles-diff <role_name-1> <role_name-2>
```

This tool fetches the inline and attached policies for two IAM Roles, combines them and sorts
them by AWS Service, then diffs the statements one by one:

* if the [Levenshtein distance](https://en.wikipedia.org/wiki/Levenshtein_distance) is under a certain
  threshold, we assume that they are probably referring to the same set of resources, and we
  print a diff
* if not, we diff the statement against an empty string.

