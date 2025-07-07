## Using Bearer for Static Analysis Security Testing

#### Install bearer CLI
[Installing Bearer CLI](https://docs.bearer.com/reference/installation/)



#### Run Bearer CLI on the source code

```bash
bearer scan . --severity critical,high,medium --format json --output Alphazap_8.1_bearer.json
```
