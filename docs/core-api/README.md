### Certisfy Core PKI Platform API

This API is for the core-api component of the Certisfy SDK, it facilitates integration into the remote PKI platform. 

The Certisfy SDK exposes an extensive set of APIs for each component, almost all of the Certisfy SDK functionality can be implemented with just
the component APIs and don't require the PKI platform API. 

The PKI platform API, which is a remote end-point API, offers what can be thought of as value-add capabilities 
that most implementations will find valuable.

You can see all functions exposed by the PKI platform API [here](https://github.com/CipherTrustee/certisfy-js/blob/master/src/core-api/api.js).

Below is documentation of various functions exposed by the PKI platform API.
    
1. `postCertIdentity({
      id_anchor_cert_sig,
      sp_uri,
      enclosed_sig,
      vouch_for_claim_identities,
      include_trust_chain,
      is_private_persona
    })`

    This function is perhaps the most crucial for the Certisfy solution suite. It allows anonymous identities
    to be attached to claims so that those claims are trustworthy, otherwise a claim is just a cryptographic
    signature that is untethered to an identity.
    
    This function operates in a completely private manner so that the PKI platform can co-sign the enclosed
    claim's identity without compromising the privacy of the owner.
    
    *This function is the only required core PKI platform API usaged, unless a claim is being generated without an identity,
    or from an identity anchor certificate, this function is a requirement.*
    
    You can learn more about identity anchoring [here](https://cipheredtrust.com/doc/#pki-id-anchoring).
    
    **Arguments**

    - `id_anchor_cert_sig`\
      The claim from the id anchor certificate linked to the certificate whose claim needs an identity generated for.
      
      This claim will contain the sha-2 hash of the identity element value and the identity element type (DLN,SSN..etc)
      in plain form.

    - `sp_uri`\
      The receiver id for whom this identity should be generated. This should be a sha-2 hash of the target
      receiver id.

    - `enclosed_sig`\
      The claim for which an identity needs to be generated.

    - `vouch_for_claim_identities`\
      If the enclosed claim contains vouched-for claims, this should be a json array string of the associated
      identities. This identity list can be extracted via a call to `certisfySDK.signer.getVouchedClaimIdentities`.
      
    - `include_trust_chain`\
      Set to `true` to attach the trust chain for the co-signed (by the PKI platform) identity.

    - `is_private_persona`\
      Set to `true` for claims created for private use.

    **Usage** 
    
    ```javascript
    const indentity = await certisfySDK.api.postCertIdentity({
                                                              id_anchor_cert_sig,
                                                              sp_uri,
                                                              enclosed_sig,
                                                              vouch_for_claim_identities,
                                                              include_trust_chain,
                                                              is_private_persona
                                                              });
    ```        
    
	Review claim objects created via the Certisfy app or the signer to see what the resulting 
    `identity` object looks like.

2. `postDHExchange(dhExchange)`

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
    
3. `getDHExchange(userCode)`

    This function retrieves a previously posted DH exchange object. The state of the returned `dhExchange`
    object reflects the state of the exchange.
    
    **Arguments**

    - `userCode`\
      This is a short lookup code. 

    **Usage** 
    
    ```javascript
    const {status,message,alice_public_key,alice_data,user_code,bob_public_key,bob_data} = await certisfySDK.api.getDHExchange(userCode);
    ```     
    

