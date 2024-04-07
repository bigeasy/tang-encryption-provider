
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

### Testing

There is little to test ouside of the interactions with the Tang server, so tests are primarily integration tests. To run the test you have to run a Tang server and provide the tests with a path the Tang server's data directory. The data directory must be read/write for the user running the test.

You can accomplish this with the `padhihomelab/tang` Docker container.

```
docker run -d -e ENTRYPOINT_RUN_AS_ROOT=1 --rm --name tang -v $HOME/etc/tang:/db -p 8080:8080 -it padhihomelab/tang
```
