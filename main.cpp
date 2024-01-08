#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <numeric>
#include <string>
#include <utility>
#include <random>
#include <vector>

#include "snippet.h"

struct Packet {
    std::unique_ptr<unsigned char[]> buf;
    int size;
};

void printMD5(unsigned char* out) {
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << static_cast<int>(out[i]);
    }
    std::cout << '\n';
}

void randomizeBuffer(std::unique_ptr<unsigned char[]>& buf, int packetSize) {
    for (int i = 0; i < packetSize; ++i) {
        buf[i] = static_cast<unsigned char>(std::rand() % 256);
    }
}

void randomizePackets(std::vector<Packet>& packets) {
    int count = 1000000;
    while (count--) {
        int packetSize = std::rand() % 200 + 100;
        auto buf = std::make_unique<unsigned char[]>(packetSize);
        randomizeBuffer(buf, packetSize);
        packets.push_back({std::move(buf), packetSize});
    }
}

void randomizeIndices(std::vector<int>& indices, int count) {
    indices.resize(count);
    std::iota(indices.begin(), indices.end(), 0);
    std::random_device rd;
    std::mt19937 g(rd());
    std::shuffle(indices.begin(), indices.end(), g);
}

void directMD5(std::vector<Packet>& packets, std::vector<int>& indices) {
    auto* out = new unsigned char[16];
    for (const auto index : indices) {
        MD5(reinterpret_cast<unsigned char*>(packets[index].buf.get()), packets[index].size, out);
        //printMD5(out);
    }
}

void unoptimizedMD5(std::vector<Packet>& packets, std::vector<int>& indices) {
    auto* out = new unsigned char[16];
    for (const auto index : indices) {
        calculate_md5(packets[index].buf.get(), packets[index].size, out);
        //printMD5(out);
    }
}

void calculate_md5_optimized(EVP_MD_CTX* mdctx, const void* buf, size_t buf_size, unsigned char* res) {
    EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(mdctx, buf, buf_size);
    EVP_DigestFinal_ex(mdctx, res, nullptr);
}

void optimizedMD5(std::vector<Packet>& packets, std::vector<int>& indices) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    auto* out = new unsigned char[MD5_DIGEST_LENGTH];
    #pragma GCC unroll 0
    for (const auto index : indices) {
        calculate_md5_optimized(mdctx, packets[index].buf.get(), packets[index].size, out);
        //printMD5(out);
    }
    EVP_MD_CTX_free(mdctx);
}

#include <cstring>
#include "md5-x86-asm.h"

template<typename HT>
void md5_init(volatile MD5_STATE<HT>* state) {
	state->A = 0x67452301;
	state->B = 0xefcdab89;
	state->C = 0x98badcfe;
	state->D = 0x10325476;
}

template<typename HT, void(&fn)(MD5_STATE<HT>*, const void*)>
void md5(volatile MD5_STATE<HT>* state, const void* __restrict__ src, size_t len) {
	md5_init<HT>(state);
	char* __restrict__ _src = (char* __restrict__)src;
	uint64_t totalLen = len << 3; // length in bits
	
	for(; len >= 64; len -= 64) {
		fn(state, _src);
		_src += 64;
	}
	len &= 63;
	
	
	// finalize
	char block[64];
	memcpy(block, _src, len);
	block[len++] = 0x80;
	
	// write this in a loop to avoid duplicating the force-inlined process_block function twice
	for(int iter = (len <= 64-8); iter < 2; iter++) {
		if(iter == 0) {
			memset(block + len, 0, 64-len);
			len = 0;
		} else {
			memset(block + len, 0, 64-8 - len);
			memcpy(block + 64-8, &totalLen, 8);
		}
		fn(state, block);
	}
}

void externalMD5(std::vector<Packet>& packets, std::vector<int>& indices) {
    volatile MD5_STATE<uint32_t> hash;
    for (const auto index : indices) {
        // different optimizations
        //md5<uint32_t, md5_block_std>(&hash, packets[index].buf, packets[index].size);
        //md5<uint32_t, md5_block_nolea>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_noleag>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_noleagh>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_cache4>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_cache8>(&hash, packet, PACKET_SIZE);
        md5<uint32_t, md5_block_cache_gopt>(&hash, packets[index].buf.get(), packets[index].size);
        //printMD5(reinterpret_cast<volatile unsigned char*>(&hash));
    }
}

#include "optimizedMD5.h"

void optimizedDirectMD5(std::vector<Packet>& packets, std::vector<int>& indices) {
    auto out = new unsigned char[16];
    for (const int index : indices) {
        OptimizedMD5(reinterpret_cast<unsigned char*>(packets[index].buf.get()), packets[index].size, out);
        //printMD5(out);
    }
}

int main() {
    std::srand(time(0));
    std::vector<Packet> packets; // first: buf, second: size
    std::vector<int> indices;
    randomizePackets(packets);
    randomizeIndices(indices, packets.size());

    auto start = std::chrono::system_clock::now();
    unoptimizedMD5(packets, indices);
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Unoptimized snippet runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";

    start = std::chrono::system_clock::now();
    optimizedMD5(packets, indices);
    end = std::chrono::system_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Optimized snippet runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";

    start = std::chrono::system_clock::now();
    externalMD5(packets, indices);
    end = std::chrono::system_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Other library runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";

    start = std::chrono::system_clock::now();
    directMD5(packets, indices);
    end = std::chrono::system_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Direct MD5 runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";

    start = std::chrono::system_clock::now();
    optimizedDirectMD5(packets, indices);
    end = std::chrono::system_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Optimized Direct MD5 runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";
}
