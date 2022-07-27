# Palantir
## Overview
Palantir is a DNS resolver that supports caching DNS answers. This project
is currently a work in progress. 

## Testing
Run palantir and wait for it to start listening on port 53
```shell
$ ./palantir
Bind finished
Listening on port 53
```

Then send a DNS query using `dig`
```shell
dig @localhost google.com
```


