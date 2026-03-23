### Certisfy Claim Signing And Integration API

This API is for the signer component of the Certisfy SDK. 

This API is used to implement this [signer](https://github.com/CipherTrustee/certisfy-signer) for developer use.

You can see all functions exposed by the signer component API [here](https://github.com/CipherTrustee/certisfy-js/blob/master/src/core-pki/signer.js).

The signer exposes the following API functions to facilitate claim creation.

1. `signClaim(signer,stringToSign,plainFields,idAnchorCertObject,receiverId,includeTrustChain,includeTrustChainInIDCertSig,vouchedForClaimIdentities,isForPrivatePersona)`

    This function performs verification of claims, it is the function called when you click the verify button
    in Certisfy and in the verifier console app.

    **Arguments**

    - `signer`\
      Certificate object, it is the object from a Certisfy app user profile. 

    - `stringToSign`\
      A string that will be signed for the claim.

    - `plainFields`\
      An optional array of plain fields to attach to the signed claim. This is the data that is being signed, typically
      the `stringToSign` is the private (masked) version of the claim data.
      
      Plain fields are decribed in the PKI platform [documentation](https://cipheredtrust.com/doc/#certisfy-client-data-structure-cert-sig-object). Also see the example usage in the
      signer console app.

	  This is optional, or pass null to ignore.
      
    - `idAnchorCertObject`\
      Certificate object, it is the object from a Certisfy app user profile. This is an id anchor certificate.
      The certificate object is described in PKI platform [documentation](https://cipheredtrust.com/doc/#certisfy-client-data-structure-cert-object).

	  This is optional if an identity need not be associated with resulting claim, or pass null to ignore.
      
    - `receiverId`\
      The receiver id (ie persona) for whom the claim is created.
      
      This is required when identity is associated with resulting claim.
      
    - `includeTrustChain`\
      Set this to `true` so signer can attempt to fetch (from registry) and attach the associated trust chain. 

    - `includeTrustChainInIDCertSig`\
      Set this to `true` so signer can attempt to fetch (from registry) and attach the associated trust chain
      when performing PKI platform identity generation.

    - `vouchedForClaimIdentities`\
      This is the result from calling `getVouchedClaimIdentities`.

	  This is optional if an identity need not be associated with resulting claim.
      
    - `isForPrivatePersona`\
      Set this to `true` or `false`. This is only needed when attaching an identity to a claim, it determines if
      a public or private persona anonymous cryptographic identity is attached to the claim, default is public.
      
	  This is optional if an identity need not be associated with resulting claim or is public persona.
      
    **Usage** 
    
    ```javascript
    const claim = await certisfySDK.signer.signClaim(signer,stringToSign,plainFields,idAnchorCertObject,receiverId,includeTrustChain,includeTrustChainInIDCertSig,vouchedForClaimIdentities,isForPrivatePersona);
    ```
           
2. `getVouchedClaimIdentities(plainFields)`

    This function will extract associated identity information for a *vouched-for* claim. If you include
    a vouched-for claim as a way of using it, there is identity associated with that claim, 
    this function extracts that information for use by the signer.    

    **Arguments**

    - `plainFields`\
      The claim data, included embedded claims that represent *vouched-for* claims.       
      
    **Usage** 
    
    ```javascript
    const vouchedForClaimIdentities = await certisfySDK.signer.getVouchedClaimIdentities(plainFields);
    ```
	
    The `vouchedForClaimIdentities` is used during claim identity generation by the Certisfy platform to ensure
    that only the true owner of a vouched-for claim can use it. The result is that the platform vouches for
    a claim that includes a vouched-for claim.    
           
3. `executeDHExchange(userCode,fnClaimProvider,useExchange)`

    This fuction will execute/complete DH exchange, playing the role of *Bob*. 
    
    **Arguments**

    - `userCode`\
      The short code for looking up the DH exchange object. 

    - `fnClaimProvider`\
      This is a callback function that will create the claim to be included in the DH exchange. 
      See the signer console app for an example of how this is done.

    - `useExchange`\
      This is optional, it can be a DH exchange object previously obtained via `certisfySDK.api.getDHExchange(userCode)`. 
      
    **Usage** 
    
    ```javascript
    const {status,dhExchange,claim} = await certisfySDK.signer.executeDHExchange(userCode,fnClaimProvider,useExchange);
    const {create_date,user_code,public_key} = dhExchange;
    ```
    
