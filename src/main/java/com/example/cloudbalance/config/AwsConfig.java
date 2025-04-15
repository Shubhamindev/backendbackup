package com.example.cloudbalance.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.AwsSessionCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;
import software.amazon.awssdk.services.sts.model.AssumeRoleResponse;
@Configuration
public class AwsConfig {
    @Value("${aws.region}")
    private String region;

    @Value("${aws.accessKey}")
    private String accessKey;

    @Value("${aws.secretKey}")
    private String secretKey;

    public S3Client createS3ClientForRole(String roleArn) {
        try {
            AwsCredentialsProvider sourceCredentials = StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(accessKey, secretKey)
            );

            StsClient stsClient = StsClient.builder()
                    .credentialsProvider(sourceCredentials)
                    .region(Region.of(region))
                    .build();

            AssumeRoleRequest roleRequest = AssumeRoleRequest.builder()
                    .roleArn(roleArn)
                    .roleSessionName("session-" + System.currentTimeMillis())
                    .durationSeconds(900) // 15 minutes
                    .build();

            AssumeRoleResponse roleResponse = stsClient.assumeRole(roleRequest);

            AwsSessionCredentials sessionCredentials = AwsSessionCredentials.create(
                    roleResponse.credentials().accessKeyId(),
                    roleResponse.credentials().secretAccessKey(),
                    roleResponse.credentials().sessionToken()
            );
            return S3Client.builder()
                    .region(Region.of(region))
                    .credentialsProvider(StaticCredentialsProvider.create(sessionCredentials))
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to assume role: " + e.getMessage(), e);
        }
    }
}
