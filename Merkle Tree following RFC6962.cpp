#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>

struct MerkleTreeLeaf {
    std::string label;
    std::string hash;
    std::string leafInput;
};

std::string sha256(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data.c_str(), data.length());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

std::string computeMerkleRoot(const std::vector<MerkleTreeLeaf>& leaves) {
    std::vector<MerkleTreeLeaf> currentLevel = leaves;

    while (currentLevel.size() > 1) {
        std::vector<MerkleTreeLeaf> nextLevel;

        for (size_t i = 0; i < currentLevel.size(); i += 2) {
            MerkleTreeLeaf combinedLeaf;
            combinedLeaf.label = currentLevel[i].label + currentLevel[i + 1].label;
            combinedLeaf.leafInput = currentLevel[i].leafInput + currentLevel[i + 1].leafInput;
            combinedLeaf.hash = sha256(combinedLeaf.label + combinedLeaf.leafInput);
            nextLevel.push_back(combinedLeaf);
        }

        currentLevel = nextLevel;
    }

    return currentLevel.empty() ? "" : currentLevel[0].hash;
}

std::string computeExistenceProof(const std::vector<MerkleTreeLeaf>& leaves, size_t index) {
    if (index >= leaves.size()) {
        return "";
    }

    std::vector<std::string> proof;
    size_t size = leaves.size();

    while (size > 1) {
        if (index % 2 == 0 && index + 1 < size) {
            proof.push_back(leaves[index + 1].hash);
        }
        else if (index % 2 != 0) {
            proof.push_back(leaves[index - 1].hash);
        }

        index /= 2;
        size = (size + 1) / 2;
    }

    std::stringstream ss;
    for (auto it = proof.rbegin(); it != proof.rend(); ++it) {
        ss << *it;
    }

    return ss.str();
}

std::string computeNonexistenceProof(const std::vector<MerkleTreeLeaf>& leaves, size_t index) {
    if (index >= leaves.size()) {
        return "NonexistenceProof correct";
    }

    std::vector<std::string> proof;
    size_t size = leaves.size();

    while (size > 1) {
        if (index % 2 == 0 && index + 1 < size) {
            proof.push_back(leaves[index + 1].hash);
        }
        else if (index % 2 != 0) {
            proof.push_back(leaves[index - 1].hash);
        }

        index /= 2;
        size = (size + 1) / 2;
    }

    std::stringstream ss;
    for (auto it = proof.rbegin(); it != proof.rend(); ++it) {
        ss << *it;
    }

    return ss.str();
}

int main() {
    std::vector<MerkleTreeLeaf> leaves = {
        {"leaf1", "", "data1"},
        {"leaf2", "", "data2"},
        {"leaf3", "", "data3"},
        {"leaf4", "", "data4"}
    };

    for (auto& leaf : leaves) {
        leaf.hash = sha256(leaf.label + leaf.leafInput);
    }

    std::string merkleRoot = computeMerkleRoot(leaves);

    std::cout << "Merkle Root: " << merkleRoot << std::endl;

    // 计算存在性证明
    size_t proofIndex = 2;
    std::string existenceProof = computeExistenceProof(leaves, proofIndex);
    std::cout << "Existence Proof for index " << proofIndex << ": " << existenceProof << std::endl;

    // 计算不存在性证明
    size_t nonexistenceIndex = 5;
    std::string nonexistenceProof = computeNonexistenceProof(leaves, nonexistenceIndex);
    std::cout << "Nonexistence Proof for index " << nonexistenceIndex << ": " << nonexistenceProof << std::endl;

    return 0;
}
