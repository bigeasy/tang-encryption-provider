
## Run Tang Server
```shell
docker run -d -p 8080:80 --name tang \
-v tang-db:/var/db/tang \
 malaiwah/tang
```

### Extract Thumbprint from Tang server
#### Install
- jq
- jose

#### Run
```shell
curl -s http://localhost:8080/adv | jq -r '.payload' | base64 --decode | jq '.keys[0]' | jose jwk thp -i -
```

## Run Example Encrypt -> Decrypt
```shell
cd cmd
./test_run.sh
```

### Configuration

The Tang documentation suggests trust on first use and then using the verify keys in the advertisement to verify and future changes to the advertisement. Tang pods are ephemeral. We cannot store the advertisement in the pod. We could store it on a host volume mounted in the pod, but the hosts are control plane nodes which are more or less ephemeral. Storing in the `etcd` cluster is no good. We really want to keep our Tang encryption provider simple. None of the other KMS encryption providers rely on external storage.

We must insist that the chain-of-trust is established by providing the Tang encryption provider with the thumbprint of a trust verify key that it will expect to find in the advertisement. It is assumed that the cluster administrator maintains the cluster through secure communication, SSH for example, so the veracity of the thumbprint is inherited from the veracity of cluster configuration.

Since we've already imposed upon the cluster administrator to configure a trusted verify key thumbprint, we will ask for exchange key by thumbprint. The exchange key thumbprint is not used to verify the exchange key. It is instead used to select the exchange key to use for encryption from the advertisement.

Now we have a method for KMSv2 rotation. The Tang encryption provider is configured with a comma separated list of verify/exchange key pairs. To select the exchange key to use for encryption it works through the list of pairs in order. The exchange key thumbprint associated with the first verify key thumbprint that matches one of the advertised verify keys is used as the encryption key. If none of the advertised verify keys match the configured verify key thumbprints, the advertisement is considered untrustworthy. If the associated exchange key thumbprint does not match any of the advertised exchange keys, we consider that a misconfiguration.

Let's assume we have an existing cluster and Tang server correctly configured for a single verify/exchange key pair. The cluster as a single thumbprint pair in its thumbprint list and the Tang server is serving only the two keys in the pair.

Rotation is now a matter of first generating a new pair of verify/exchange keys and advertising them from Tang. We then add the thumbprints of the new verify/exchange key pair to end of the thumbprint list and rollout the configuration change on the control plane. The final step is to delete the outgoing verify key from the Tang server. The thumbprint of the previous verify key no longer matches any of the advertised keys, the Tang encryption provider proceeds to the next pair. The new exchange key is returned to the Kube API Server as the key id and that triggers a KMSv2 key rotation.

Give a while and the rotation is complete. You can remove the thumbprints from the Tang encryption provider configuration and rotate, or you could wait until the next rotation to do that when you append a new thumbprint pair.

An alternative to thumbprints as environment variables is to create a secure thumbprint server. This is an HTTPS server that will serve a thumbprints file that contains the list. This is like trust on first use, but with verification. The verification comes from the root certificate authority of the HTTPS client that requests the thumbprint file, then verifying the HTTPS server certificate with the root certificate, the basic trust involved with an HTTPS GET. The cluster administrator merely needs to ensure that the cluster node has the root certificate. You can use your internal CA if you have one, or use a Let's encrypt certificate and your existing web infrastructure, if you have that.

Rotation is now a matter of adding a new verify/encrypt key pair to the Tang server, deleting the verify key of the outgoing key pair, then updating the thumbprint file with the thumbprints of the keys in the verify/encrypt key pair. No lists necessary. You can perform this at once in a script, so long as it happens in less than a second, or a minute, or if you don't mind the Tang encryption provider being unhealthy while you fiddle around. Order is important, though. Deleting the old verify key will cause the Tang encryption provider to GET the new thumbprints. If you update the thumbprints file then one of your nodes may query it and advance while the others use their cached thumbprints. Removing the verify key forces them to all update on their next write.

After rotation you can delete the outgoing exchange key. Or wait, delete it the next time you're rotating.

KMSv1 rotation is much simpler. When you rotate you add a new verify/encrypt key pair to the Tang server. You update the thumbprints of a single verify/encrypt key pair in the Tang encryption provider configuration. You then do a rolling restart. The Tang encryption provider will start using the new keys to encrypt immediately, but it doesn't matter with KMSv1. You run the secret replacement command TK. You can then delete the outgoing keys, or wait until the next time you rotate to delete them.

### KMSv2 Rotation

Key rotation begins by adding a new pair of verify

### Testing

There is little to test ouside of the interactions with the Tang server, so tests are primarily integration tests. To run the test you have to run a Tang server and provide the tests with a path the Tang server's data directory. The data directory must be read/write for the user running the test.

You can accomplish this with the `padhihomelab/tang` Docker container.

```
docker run -d -e ENTRYPOINT_RUN_AS_ROOT=1 --rm --name tang -v $HOME/etc/tang:/db -p 8080:8080 -it padhihomelab/tang
```
