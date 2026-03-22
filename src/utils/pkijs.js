	/************************************For browser environment******************************************/
	import * as asn1js from '../pkijs/asn1js.js';
    import * as pkijs from '../pkijs/pkijs.es.js';
    /*****************************************************************************************************/

    /************************************For nodejs environment*******************************************
    import * as pkijs from 'pkijs';
    import * as asn1js from 'asn1js';

	//import crypto from 'node:crypto';
    //Get the crypto extension
    //const crypto = pkijs.getCrypto(true);
    *******************************************************************************************************/

	export {asn1js,pkijs}