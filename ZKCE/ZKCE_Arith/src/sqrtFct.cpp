void Scheme::sqrt(Ciphertext& cipher, long logp) {
	Ciphertext cipher2;
	square(cipher2, cipher);
	reScaleByAndEqual(cipher2, logp); // cipher2.logq : logq - logp

	Ciphertext cipher4;
	square(cipher4, cipher2);
	reScaleByAndEqual(cipher4, logp); // cipher4.logq : logq -2logp

	Ciphertext cipher8;
	square(cipher8, cipher4);
	reScaleByAndEqual(cipher8, logp); // cipher4.logq : logq -2logp


	RR c = 45/144; //a0/a1
	Ciphertext cipher01;
	addConst(cipher01, cipher, c, logp); // cipher01.logq : logq

	c = 288/323; //a1
	multByConstAndEqual(cipher01, c, logp);
	reScaleByAndEqual(cipher01, logp); // cipher01.logq : logq - logp

	c = -125/24; //a2/a3
	Ciphertext cipher23;
	addConst(cipher23, cipher, c, logp); // cipher23.logq : logq

	c = 44352/1009375;//a3
	multByConstAndEqual(cipher23, c, logp);
	reScaleByAndEqual(cipher23, logp); // cipher23.logq : logq - logp

	multAndEqual(cipher23, cipher2);
	reScaleByAndEqual(cipher23, logp); // cipher23.logq : logq - 2logp

	addAndEqual(cipher23, cipher01); // cipher23.logq : logq - 2logp

	c = -5625/392; //a4/a5
	Ciphertext cipher45;
	addConst(cipher45, cipher, c, logp); // cipher45.logq : logq

	c = 224224/630859375; //a5
	multByConstAndEqual(cipher45, c, logp);
	reScaleByAndEqual(cipher45, logp); // cipher45.logq : logq - logp

	c = -15925/352; // a6/a7
	addConstAndEqual(cipher, c, logp); // cipher.logq : logq

	c = 25344/78857421875; // a7
	multByConstAndEqual(cipher, c, logp);
	reScaleByAndEqual(cipher, logp); // cipher.logq : logq - logp

	multAndEqual(cipher, cipher2);
	reScaleByAndEqual(cipher, logp); // cipher.logq : logq - 2logp

	modDownByAndEqual(cipher45, logp); // cipher45.logq : logq - 2logp
	addAndEqual(cipher, cipher45); // cipher.logq : logq - 2logp

	multAndEqual(cipher, cipher4);
	reScaleByAndEqual(cipher, logp); // cipher.logq : logq - 3logp

	modDownByAndEqual(cipher23, logp);
	addAndEqual(cipher, cipher23); // cipher.logq : logq - 3logp


	c = -1716./579833984375; //a8
	multByConstAndEqual(cipher8, c, logp);
	reScaleByAndEqual(cipher8, logp); // cipher45.logq : logq - logp
	addAndEqual(cipher, cipher8); // cipher.logq : logq - 3logp
}