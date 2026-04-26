const nativeBinding = require('./server_utilities.linux-x64-gnu.node');
if (!nativeBinding) {
  throw Error("Couldn't load binary lib");
}
module.exports = nativeBinding
module.exports.addVotes = nativeBinding.addVotes
module.exports.createRequest = nativeBinding.createRequest
module.exports.decryptResult = nativeBinding.decryptResult
module.exports.eccDecrypt = nativeBinding.eccDecrypt
module.exports.eccEncrypt = nativeBinding.eccEncrypt
module.exports.encryptVote = nativeBinding.encryptVote
module.exports.generateAcc = nativeBinding.generateAcc
module.exports.generateElgamalKeypair = nativeBinding.generateElgamalKeypair
module.exports.generateRsaKeypair = nativeBinding.generateRsaKeypair
module.exports.sign = nativeBinding.sign
module.exports.unblind = nativeBinding.unblind
module.exports.verify = nativeBinding.verify
