terraform {
  required_version = ">= 1.5.0"
}

resource "aws_iam_role" "ci_runner" {
  name = "lab-ci-runner-least-privilege-example"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "codebuild.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_policy" "ci_limited" {
  name = "lab-ci-runner-limited-example"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ci_limited" {
  role       = aws_iam_role.ci_runner.name
  policy_arn = aws_iam_policy.ci_limited.arn
}
