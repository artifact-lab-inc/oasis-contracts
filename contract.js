export async function createIdentity(userAddress) {
	console.log(`[createIdentity] Starting for userAddress: ${userAddress}`);
	return withRetry(async () => {
		try {
			const { salt, sapphireRpc } = crypto;
			const { PRIVATE_KEY } = process.env;

			const assignee = web3.utils.keccak256(userAddress);
			console.log(`[createIdentity] Generated assignee hash: ${assignee}`);
			console.log(`[createIdentity] Using salt: ${salt}`);

			console.log(
				`[createIdentity] Connecting to Sapphire RPC: ${sapphireRpc}`
			);
			const wallet = sapphire.wrap(new ethers.Wallet(PRIVATE_KEY));
			const provider = new ethers.providers.JsonRpcProvider(sapphireRpc);
			const connectedWallet = wallet.connect(provider);

			console.log(
				`[createIdentity] Creating contract instance at address: ${contractAddresses.OmniKeyStore}`
			);
			const contract = new ethers.Contract(
				contractAddresses.OmniKeyStore,
				omni,
				connectedWallet
			);

			console.log(
				`[createIdentity] Sending transaction with parameters - assignee: ${assignee}, salt: ${salt}`
			);

			// Send the transaction
			const tx = await contract.createIdentity(assignee, salt);
			console.log(`[createIdentity] Transaction sent, hash: ${tx.hash}`);

			// Wait for confirmation
			console.log(`[createIdentity] Waiting for transaction confirmation...`);
			const receipt = await tx.wait();
			console.log(
				`[createIdentity] Transaction confirmed, blockNumber: ${receipt.blockNumber}`
			);

			return receipt;
		} catch (error) {
			console.error(`[createIdentity] Error encountered: ${error.message}`);

			throw new ContractError(error.message, "OmniKeyStore", "createIdentity", [
				userAddress,
				salt,
			]);
		}
	});
}

export async function fetchIdentity(userAddress) {
	console.log(`[fetchIdentity] Starting for userAddress: ${userAddress}`);
	return withRetry(async () => {
		try {
			const { sapphireRpc } = crypto;
			const { PRIVATE_KEY, SECRET_KEY } = process.env;

			console.log(`[fetchIdentity] Connecting to Sapphire RPC: ${sapphireRpc}`);
			const sdk = ThirdwebSDK.fromPrivateKey(PRIVATE_KEY, sapphireRpc, {
				secretKey: SECRET_KEY,
			});

			const assignee = web3.utils.keccak256(userAddress);
			console.log(`[fetchIdentity] Generated assignee hash: ${assignee}`);

			console.log(
				`[fetchIdentity] Getting contract at address: ${contractAddresses.OmniKeyStore}`
			);
			const contract = await sdk.getContractFromAbi(
				contractAddresses.OmniKeyStore,
				omni
			);

			console.log(
				`[fetchIdentity] Calling contract method "fetchIdentity" with assignee: ${assignee}`
			);
			const newIdentityData = await contract.call("fetchIdentity", [assignee]);

			console.log(`[fetchIdentity] Successfully retrieved identity data`);
			return newIdentityData.toString();
		} catch (error) {
			console.error(`[fetchIdentity] Error encountered: ${error.message}`);
			throw new ContractError(error.message, "OmniKeyStore", "fetchIdentity", [
				userAddress,
			]);
		}
	});
}
