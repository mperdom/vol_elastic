# VOL-ASTIC
Volatility integrated with ElasticSearch(ES) and Kibana

## Overview
Volatilty gives users the ability to ask for their output in a specific format such as text,json,html, etc. This unified output concept allows for users to run plugins and output the results how they see fit. Examples of existing renderers and their outputs can be found on their volatility wiki found [here](https://github.com/volatilityfoundation/volatility/wiki/Unified-Output)

The aim of this project was to create an ElasticSearch renderer that can format the output to an ES format and then automatically export the results to ES. I then decided to create a Kibana dashboard to better visualize the results exported in a dashboard in Kibana. 

After being able to run this locally, I decided to automate the process of building up an Elastic stack leveraging AWS. I did this to test the renderer in a linux environment, and also to make it so that anyone can leverage the automation and run this renderer with minimal effort.

Huge credit to Dolos Development for supplying the base of the code for the Volatility ES Renderer.
Dolos Development repo can be found here: https://github.com/dolosdevelopment/volatility

### AWS Automation
This documentation will assume that the user has created their own AWS account.

#### Define EC2 KeyPair
Before beginning AWS deployment, a user must first define their EC2 keypair to ssh to any EC2 instance. Refer to AWS documentation [here](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html).

#### Define S3 Bucket
This will simply serve the purpose of storing your memory files, I could have removed the need for a S3 bucket, but it's a nice resource to have and include so I left it in as a requirement. One can simply choose to remove the dependency if they so choose.

#### Deploying - EC2 Instance
Under the aws folder exists an `elk_ec2.yml` file that provisions the AWS EC2 instance. It is designed with automation in mind. The easiest way to provision an EC2 instance is to use the AWS console. Head over to the `CloudFormation` resource and click on `Create stack`. There are two options of specifying a CloudFormation template:

- Amazon S3 URL: Upload the preferred version of the `elk_ec2.yml` file and just provide the object url of that file to CloudFormation
- Upload a template file: Allows the user to choose their version of `elk_ec2.yml` file from their local machine

For stack details, define the stack name however you choose :) 
Next, there are five parameters required to fill in, each serve a purpose to let the user define their inputs.

- KeyName: This is the only component that the user must create on their own for their specific AWS account. The user must first define a EC@ keypair, and use that name for this parameter. This is the key that will be used to ssh to your instance
- InstanceType: This will define the instance type that you wish to deploy. The default is the minimum requirement to run ES/Kibana
- SSHLocation: This defines the range of ip addresses that can ssh to the EC2 instance. Default is all ip addresses
- S3BucketName: The name of the S3 bucket that the EC2 instance can upload/download files to/from
- MemoryFile: The name of any memory file that you wish to download automatically to the EC2 instance upon startup

Next, define tag names for your stack if you'd like, or skip onto the next step.

Review your stack details and then check the box that "Acknowledge(s) that AWS CloudFormation might create IAM resources". Then click create stack.

#### Sit back and relax
CloudFormation will begin to deploy your template, and will notify the user if there were any issues. Once everything completed successfully, the EC2 instance will take a few minutes to fully run the user data. Once completed, the instance will be running both ElasticSearch and Kibana








