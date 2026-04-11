	import * as mainEntry from './main.js';

	async function createSDK(config){
      
      	const sdk = Object.assign({
          helperUtil:mainEntry.helperUtil,
          cryptoUtil:mainEntry.cryptoUtil,
          certUtil:mainEntry.certUtil,
          
          certStore:mainEntry.certStore,
          claimData:mainEntry.claimData,
          signer:mainEntry.certisfySigner,
          verifier:mainEntry.certisfyVerifier,
          certGen:mainEntry.certGen,
          api:mainEntry.certisfyAPI,
          
          apiAuth:mainEntry.certisfyAPIAuth
        },mainEntry)
      
    	sdk.configure({config,sdk});
      	await sdk.loadTrustRoots();
        return sdk;
    }

	export{createSDK}

