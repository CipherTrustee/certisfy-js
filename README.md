This is the core implementation SDK of Certisfy for Javascript.

It consists of a [signer](https://github.com/CipherTrustee/certisfy-signer) and a [verifier](https://github.com/CipherTrustee/certisfy-verifier).


### Common API

The following API functions are common APIs used by both the Certisfy signer and verifier.

    
1. `postDHExchange(dhExchange)`

    This function will post a DH exchange object. It is used for both the *Alice* and *Bob* roles of
    a DH exchange, the properties of the `dhExchange` object vary by role.
    
    **Arguments**

    - `dhExchange`\
      When initiating an exchange, ie playing role *Alice*, this object takes the form `{alice_public_key,alice_data}`.
      `alice_public_key` is the base64 encoded public key. `alice_data` is optional, it might include the receiver
      id, see [verifier](https://github.com/CipherTrustee/certisfy-verifier) for example usage.
      
      When executing/completing an exchange, ie playing role *Bob*, this object takes the form `{user_code,bob_public_key,bob_data}`.
      `bob_public_key` is the base64 encoded public key. `bob_data` is the cipher text of the claim, see [signer](https://github.com/CipherTrustee/certisfy-signer) for example usage.
      
      `user_code` is the lookup code for the exchange.

    **Usage** 
    
    ```javascript
    const {status,message,userCode} = await certisfySDK.api.postDHExchange(dhExchange);
    ```    
    `userCode` is returned in response to a newly initiated exchange.
    
2. `getDHExchange(userCode)`

    This function retrieves a previously posted DH exchange object. The state of the returned `dhExchange`
    object reflects the state of the exchange.
    
    **Arguments**

    - `userCode`\
      This is a short lookup code. 

    **Usage** 
    
    ```javascript
    const {status,message,alice_public_key,alice_data,user_code,bob_public_key,bob_data} = await certisfySDK.api.getDHExchange(userCode);
    ```     

