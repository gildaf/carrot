cross regional aws client for getting info about active VPCs

# env variables
* AWS_CREDENTIALS:
    * description: full path the aws credentials file. 
    * default: ~/.aws/credentials
* AWS_PROFILE:
    * description: aws profile name to use
    * default: "default"

# building
* cargo build --release

#running
*  AWS_PROFILE=gil=qa target/release/carrot