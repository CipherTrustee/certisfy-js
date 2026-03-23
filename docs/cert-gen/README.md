### Certisfy Certificate Provisioning API

This API facilitates automated provisioning of certificates by trust anchors. For instance let's say you
are a government agency (ex DMV) that wants to issue certificates for trusted information to the public,
you can use this API to implement such services.

You can see all functions exposed by the cert-gen component API [here](https://github.com/CipherTrustee/certisfy-js/blob/master/src/core-pki/cert-gen.js).

Below is documentation of various functions exposed by the cert-gen component API.
    
1. `createCSR(csrPayload,isPrivate,idCert,identityCertSig,certIdentity,keyPair,encKeyPair,payloadEncryptionKey,useStrongIdProofing,includeIdCertSigTrustChain,isForPrivatePersona,encryptIssuerFingerPrint)`

    This function can be used to create a certificate signing request.
    
    **Arguments**

    - `csrPayload`\
      This represents the information that will be verified and have a certificate issued for it.

    - `isPrivate`\
      Set to `true` to mask the data encoded on the resulting certificate, except for trust anchor certificates (including delegates),
      almost all certificates should be private.

    - `idCert`\
      This is the id anchor certificate that will be linked to this csr's resulting certificate. It can be null if this csr is
      for an identity anchor certificate.

    - `identityCertSig`\
      This is the id anchor claim that can be used to id proof during verification before a certificate can be
      issued. Review the Certisfy app documentation on id proofing to see why this is important.

    - `certIdentity`\
      When initiating an exchange, ie playing role *Alice*, this object takes the form `{alice_public_key,alice_data}`.
      `alice_public_key` is the base64 encoded public key. `alice_data` is optional, it might include the receiver
      id, see [verifier](https://github.com/CipherTrustee/certisfy-verifier) for example usage.

    - `keyPair`\
      A custom key pair to use for the CSR, otherwise one will be generated.

    - `encKeyPair`\
      A custom key pair for encryption/decryption operations associated with the resulting certificate. One
      will be generated if this is set o null.

    - `payloadEncryptionKey`\
      An AES key for encrypting the resulting csr payload, a new key will be generated if this is null.

    - `useStrongIdProofing`\
      See Certisfy app documentation for what strong id proofing means. Set to `true` to enable it.

    - `includeIdCertSigTrustChain`\
      Set to `true` to attach trust chain when doing identity generation for id claim.

    - `isForPrivatePersona`\
      Set to `true` marks the resulting certificate as private persona use, the alternative and default is public
      persona use.

    - `encryptIssuerFingerPrint`\
      Set to `true` to encrypt the issuer information on the resulting certificate for enhanced privacy. This
      requires the use of the PKI platform API.

    **Usage** 
    
    ```javascript
    const {
      finger_print,
      encryptedPayload,
      encryptionKey,
      csr,
      signedDocument,
      asymDecryptionKey,
      asymEncryptionKey
    } = await certisfySDK.certGen.createCSR(csrPayload,isPrivate,idCert,_identityCertSig,certIdentity,keyPair,encKeyPair,payloadEncryptionKey,useStrongIdProofing,includeIdCertSigTrustChain,isForPrivatePersona,encryptIssuerFingerPrint);
    ```    
    
    
2. `createCert(csrPEM,startDateText,expireDateText,privateKey,delegateSigningAuthority,lateralLimit,issuer,approvedCSRFields,encryptIssuerFingerPrint)`

    This function uses provided certificate signing request information to issue a certificate.
    
    **Arguments**

    - `csrPEM`\
      The PEM encoded CSR. 

    - `startDateText`\
      Start date for validity of certificate.

    - `expireDateText`\
      Expiration date for validity of certificate.

    - `privateKey`\
      Private key that will be used to sign CSR and issue certificate.
      
    - `delegateSigningAuthority`\
      Set to indicate trust anchor delegation right, this corresponds to `pki-maximum-delegates`. Basically
      how many levels of delegation the resulting certificate can have. This should be `null` if the resulting
      certificate is not a trust anchor certificate.

    - `lateralLimit`\
      This is used to limit how many certificates a trust anchor certificate can issue, it is the breadth
      counter part to the depth of delegation. This is only enforceable at the PKI platform level, in other words
      only controls at the PKI registry, certificates can still be issued without being in the registry.

    - `issuer`\
      The certificate that will be issuing the resulting certificate. 

    - `approvedCSRFields`\
      The fields that are considered approved by the trust anchor, you must cross check CSRs to ensure the
      data they contain match your expectation, otherwise a CSR can contain information that isn't valid or
      verified and have a certificate issued for it.

    - `encryptIssuerFingerPrint`\
      This is a function that will encrypt the issuer finger print to enhance privacy. There is default implemtation
      of this function in `certisfySDK.getEncryptedIssuerFingerPrint`, that function can be passed. This requires
      use of the PKI platform API.
      
    **Usage** 
    
    ```javascript
    const {
      signerSignature,
      certificate,
      finger_print,
      certPEM,
    } = await certisfySDK.certGen.createCert(csrPEM,startDateText,expireDateText,privateKey,delegateSigningAuthority,lateralLimit,issuer,approvedCSRFields,certisfySDK.getEncryptedIssuerFingerPrint);
    ```     

