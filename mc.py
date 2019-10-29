# from web3 import Web3

# url = "http://127.0.0.1:22000"
# w3 = Web3(Web3.HTTPProvider(url))
# print("Connected: ", w3.isConnected())
# account_1 = "0x82e0f86124e3a7890226d080a7ce64c20189c7f0"
# # print(w3.fromWei(w3.eth.getBalance(account_1), "ether"))
# with open('fromscratch/new-node-1/keystore/UTC--2019-10-07T14-45-44.080697665Z--82e0f86124e3a7890226d080a7ce64c20189c7f0', 'r') as f:
# 	private_key = w3.eth.account.decrypt(f.read(), 'root')

# nonce = w3.eth.getTransactionCount(w3.toChecksumAddress(account_1))
# print(nonce)
# tx = {
# 	'nonce': "0x0",
# 	"privateFor": [],
# 	# 'from': w3.toChecksumAddress(account_1),
# 	'gas': 500000,
# 	# 'gasPrice': '0x00',
# 	# 'chainId': 10,
# 	'gasPrice': w3.toWei('20', 'gwei'),
# 	'data': '606060405260a18060106000396000f360606040526000357c01000000000000000000000000000000000000000000000000000000009004806360fe47b11460435780636d4ce63c14605d57603f565b6002565b34600257605b60048080359060200190919050506082565b005b34600257606c60048050506090565b6040518082815260200191505060405180910390f35b806000600050819055505b50565b60006000600050549050609e565b9056'
# }
# # tx = {
# # 	'nonce': nonce,
# # 	'from': w3.toChecksumAddress(account_1),
# # 	'to': w3.toChecksumAddress("0x810e5372090ac8e6ec99f01ae6d0adcd089a0d41"),
# # 	# 'gas': 5000000,
# # 	# 'gasPrice': w3.toWei('50', 'gwei'),
# # 	'data': 'abcdef98761234'
# # }
# # signed_tx = w3.eth.signTransaction(tx)
# signed_tx = w3.eth.account.signTransaction(tx, private_key)
# # print(signed_tx.rawTransaction)
# tx_hash = w3.eth.sendRawTransaction(signed_tx.rawTransaction)
# # tx_hash = w3.eth.sendTransaction(tx)

# # print(w3.toHex(tx_hash))
# # print(private_key)


# # abi = [{"constant":"false","inputs":[{"name":"x","type":"uint256"}],"name":"set","outputs":[],"payable":"false","type":"function","stateMutability":"nonpayable"},{"constant":"true","inputs":[],"name":"get","outputs":[{"name":"retVal","type":"uint256"}],"payable":"false","type":"function","stateMutability":"view"}]
# # contract = w3.eth.contract(abi=abi, address=w3.toChecksumAddress("0x810e5372090ac8e6ec99f01ae6d0adcd089a0d41"))
# # print(hex(contract.functions.get().call()))

from Savoir import Savoir

rpcuser = 'multichainrpc'
rpcpasswd = 'EM2YQvCpHuk39cSuDwwKWgV8VnpTqeUeVLepmoEQH4JC'
rpchost = '127.0.0.1'
rpcport = '4770'
chainname = 'chain1'
stream = 'stream1'

def getApi():
	return Savoir(rpcuser, rpcpasswd, rpchost, rpcport, chainname)

def publishItem(api, id, type, data, sig):
	d = {'json':{'id':id, 'type':type, 'data':data, 'sig':sig}}
	return api.publish(stream, 'key1', d)

def streamInfo(api):
	info = api.liststreams(stream)
	return info[0]['items']

def getItems(api, count):
	return api.liststreamitems(stream, False, count)

# api = getApi()
# print(getItems(api, 2))
# print(streamInfo(api, 'stream1'))
# print(api.liststreamitems('stream1')[0])
# print(api.liststreamitems('stream1')[1])
