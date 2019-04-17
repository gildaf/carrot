cross regional aws client for getting info about active VPCs

# Environment Variables
* AWS_CREDENTIALS:
    * description: full path the aws credentials file. 
    * default: ~/.aws/credentials
* AWS_PROFILE:
    * description: aws profile name to use
    * default: "default"

# Building
```bash
cargo build --release
```

# Running
```bash
AWS_PROFILE=<profile-name> target/release/carrot
```