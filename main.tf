provider "aws" {
}

resource "random_id" "id" {
  byte_length = 8
}

resource "aws_iam_role" "appsync" {
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "appsync.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF
}

data "aws_iam_policy_document" "appsync" {
  statement {
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents"
    ]
    resources = [
      "arn:aws:logs:*:*:*"
    ]
  }
  statement {
    actions = [
      "cognito-idp:AdminCreateUser",
    ]
    resources = [
			aws_cognito_user_pool.pool.arn
    ]
  }
  statement {
    actions = [
      "dynamodb:PutItem",
      "dynamodb:Scan",
    ]
    resources = [
      aws_dynamodb_table.user.arn,
    ]
  }
}

resource "aws_iam_role_policy" "appsync_logs" {
  role   = aws_iam_role.appsync.id
  policy = data.aws_iam_policy_document.appsync.json
}

resource "aws_appsync_graphql_api" "appsync" {
  name                = "appsync_test"
  schema              = file("schema.graphql")
  authentication_type = "AWS_IAM"
  log_config {
    cloudwatch_logs_role_arn = aws_iam_role.appsync.arn
    field_log_level          = "ALL"
  }
}

resource "aws_cloudwatch_log_group" "loggroup" {
  name              = "/aws/appsync/apis/${aws_appsync_graphql_api.appsync.id}"
  retention_in_days = 14
}

resource "aws_dynamodb_table" "user" {
  name         = "user-${random_id.id.hex}"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}


resource "aws_cognito_user_pool" "pool" {
  name = "test-${random_id.id.hex}"
}

data "aws_arn" "cognito" {
  arn = aws_cognito_user_pool.pool.arn
}

resource "aws_appsync_datasource" "cognito" {
  api_id           = aws_appsync_graphql_api.appsync.id
  name             = "cognito"
  service_role_arn = aws_iam_role.appsync.arn
  type             = "HTTP"
	http_config {
		endpoint = "https://cognito-idp.${data.aws_arn.cognito.region}.amazonaws.com"
		authorization_config {
			authorization_type = "AWS_IAM"
			aws_iam_config {
				signing_region = data.aws_arn.cognito.region
				signing_service_name = "cognito-idp"
			}
		}
	}
}

resource "aws_appsync_datasource" "ddb_users" {
  api_id           = aws_appsync_graphql_api.appsync.id
  name             = "ddb_users"
  service_role_arn = aws_iam_role.appsync.arn
  type             = "AMAZON_DYNAMODB"
  dynamodb_config {
    table_name = aws_dynamodb_table.user.name
  }
}

resource "aws_appsync_function" "Mutation_createUser_1" {
  api_id      = aws_appsync_graphql_api.appsync.id
	name = "func1"
  data_source = aws_appsync_datasource.cognito.name
	request_mapping_template = <<EOF
{
	"version": "2018-05-29",
	"method": "POST",
	"params": {
		"headers": {
			"Content-Type": "application/x-amz-json-1.1",
			"X-Amz-Target": "AWSCognitoIdentityProviderService.AdminCreateUser"
		},
		"body":$util.toJson({
			"UserAttributes": [
				{
					"Name": "email",
					"Value": $ctx.args.email
				}
			],
			"Username": "$util.autoId()",
			"UserPoolId": "${aws_cognito_user_pool.pool.id}"
		})
	},
	"resourcePath": "/"
}
EOF

	response_mapping_template = <<EOF
#if ($ctx.error)
	$util.error($ctx.error.message, $ctx.error.type)
#end
#if ($ctx.result.statusCode < 200 || $ctx.result.statusCode >= 300)
	$util.error($ctx.result.body, "StatusCode$ctx.result.statusCode")
#end
$util.toJson($util.parseJson($ctx.result.body).User.Username)
EOF
}

resource "aws_appsync_function" "Mutation_createUser_2" {
  api_id            = aws_appsync_graphql_api.appsync.id
	name = "func2"
  data_source       = aws_appsync_datasource.ddb_users.name
  request_mapping_template  = <<EOF
{
	"version" : "2018-05-29",
	"operation" : "PutItem",
	"key" : {
		"id" : {"S": $util.toJson($ctx.prev.result)}
	}
}
EOF
  response_mapping_template = <<EOF
#if($ctx.error)
	$util.error($ctx.error.message, $ctx.error.type)
#end
$util.toJson($ctx.result)
EOF
}

resource "aws_appsync_resolver" "Mutation_createUser" {
  api_id      = aws_appsync_graphql_api.appsync.id
  type        = "Mutation"
  field       = "createUser"
  request_template  = "{}"
  response_template = "$util.toJson($ctx.result)"
  kind              = "PIPELINE"
  pipeline_config {
    functions = [
      aws_appsync_function.Mutation_createUser_1.function_id,
      aws_appsync_function.Mutation_createUser_2.function_id,
    ]
  }
}

resource "aws_appsync_resolver" "Query_listUsers" {
  api_id            = aws_appsync_graphql_api.appsync.id
  type              = "Query"
  field             = "listUsers"
  data_source       = aws_appsync_datasource.ddb_users.name
  request_template  = <<EOF
{
	"version" : "2018-05-29",
	"operation" : "Scan"
}
EOF
  response_template = <<EOF
#if($ctx.error)
	$util.error($ctx.error.message, $ctx.error.type)
#end
$utils.toJson($ctx.result.items)
EOF
}
