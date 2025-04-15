package com.example.cloudbalance.service;

import com.example.cloudbalance.config.AwsConfig;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.Bucket;
import software.amazon.awssdk.services.s3.model.ListBucketsResponse;
import org.springframework.beans.factory.annotation.Value;

import java.util.List;
import java.util.stream.Collectors;

@Service
public class S3Service {
    private final AwsConfig awsConfig;
    private final String region;

    public S3Service(AwsConfig awsConfig, @Value("${aws.region}") String region) {
        this.awsConfig = awsConfig;
        this.region = region;
    }

    public List<String> listBuckets(String roleArn) {
        S3Client s3Client = null;
        try {
            s3Client = awsConfig.createS3ClientForRole(roleArn);
            ListBucketsResponse response = s3Client.listBuckets();
            return response.buckets().stream()
                    .map(Bucket::name)
                    .collect(Collectors.toList());
        } finally {
            if (s3Client != null) {
                s3Client.close();
            }
        }
    }
}