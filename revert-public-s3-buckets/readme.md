# Remove Public Access From S3 Buckets

This AWS lambda function remove public access granted to S3 buckets. It is triggered by CloudWatch Events that list for bucket creation, bucket ACL changes, or bucket policy changes

It validates that the user who made the change is not part of a specific group. If the user is in the correct group the function sends an alert. If the user is not aprt of the group the access is removed and alert is sent.

## Requirements
1. Python 3.7+
2. Environment variables
a. GROUP_ARN - Special Group of Users who are allowed to made buckets public like system admins
b. SNS_TOPIC - SNS Topic to send alerts to regarging the bucket being made public