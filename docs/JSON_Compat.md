# Description of JSON compatibility issues, and potential solutions

## Problem Statement

Iguana currently lacks compatibility for anything other than JSON-RPC 1.0.  BLUR does not have compatibility with JSON-RPC 1.0, as we use the 2.0 specification.

### Iguana State

Iguana needs JSON-RPC 1.0-compliant responses

### Blur State

BLUR has two separate options for the formatting of responses over RPC.

(Note: Our existing RPC interface uses `http://localhost:21111/json_rpc` as an endpoint.  Those endpoints have been modified, in attempts to bridge gap between `bitcoind` semantics, and `blurd` semantics)

**1.) JSON-RPC 2.0 Compliant:**

Example: 

```
$ curl -X POST -d '{"method": "getblockhash", "params": {"height":1000}}' http://localhost:21111/
```

Response:

```
{
  "id": 0,
  "jsonrpc": "2.0",
  "result": {
    "hash": "b41f3552b0b169fde52f4047d4e3b35516c1e973b4686c29ce1d75d9228b7db3",
    "status": "OK"
  }
}
```

**2.) Binary RPC Methods:**

(Note: API endpoints for these simply have the `method` field from a given JSON-RPC call appended to the end of the URI)

Example:

```
curl -X POST -d '{"params": [1000]}' http://localhost:21111/getblockhash
```

Response:

```
{
  "hash": "59b031d83bd562a36a355d5a0ff223f55a28134bb1ebb82da7d4afa92c06644c",
  "status": "OK"
}
```

**Neither of these work out-of-the-box, due to differences in the way iguana creates requests/reads responses**.


Iguana is able to call the JSON-RPC 2.0 method, however, response does not align with 1.0 spec... so iguana can't understand it.  

Conversely, in format **2** (binary RPC methods), URL in iguana calls doesn't align with the binary endpoints.


## Visible Solutions

**A.)** @tonymorony suggested that an intermediary server to translate between specs could work.  While we could do that, using <a href="https://github.com/cinemast/libjson-rpc-cpp">`libjson-rpc-cpp`</a>... doing so raises concerns about the security of an intermediary abstract stub server.

**B.)** Assuming `iguana` can parse the output of the binary methods properly, the quickest solution seems to be a wrapper, which appends the `method`, to the end of the URL.  The `method` does not need removed from request... because our daemon will simply ignore this field, even if present, when dealing with binary endpoints.  

<u>Disambiguation of Solution No. 2:</u>

For example, if we are calling a binary method, we can simply call the following (with no need to remove `method` field from original call):

```
curl --data-binary '{"method": "getblockhash", "params": [1000]}' http://localhost:21111/getblockhash
```

This, again, generates the binary response we are looking for:

```
{
  "hash": "59b031d83bd562a36a355d5a0ff223f55a28134bb1ebb82da7d4afa92c06644c",
  "status": "OK"
}
```

**C.)** Add support to either `iguana` for JSON-RPC 2.0, or add support to `blurd` for JSON-RPC 1.0 


## Summary

It seems to me that the simplest route forward is a wrapper to modify structure of `iguana` curl calls.

An intermediary server would likely be easier than adding full support for incompatible specs to either daemon. However, it also raises concerns about security.

If netiher of those options work, full support for alternative specs is a last resort.

So, in order of preference, based on efficient use-of-time:

**Solution B > Solution A > Solution C** 