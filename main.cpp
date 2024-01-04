#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "snippet.h"

constexpr int PACKET_SIZE = 200;

void printMD5(unsigned char* out) {
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        std::cout << std::hex << static_cast<int>(out[i]);
    }
    std::cout << '\n';
}

void randomizeBuffer(unsigned char* buf) {
    for (int i = 0; i < PACKET_SIZE; ++i) {
        buf[i] = static_cast<unsigned char>(std::rand() % 256);
    }
}

void randomizePackets(std::vector<void*>& packets) {
    int count = 1000000;
    while (count--) {
        auto buf = new unsigned char[PACKET_SIZE];
        randomizeBuffer(buf);
        packets.push_back(buf);
    }
}

void unoptimizedMD5(std::vector<void*>& packets) {
    auto* out = new unsigned char[MD5_DIGEST_LENGTH];
    for (const auto packet : packets) {
        calculate_md5(packet, PACKET_SIZE, out);
        //printMD5(out);
    }
}

void calculate_md5_optimized(EVP_MD_CTX* mdctx, const void* buf, size_t buf_size, unsigned char* res) {
    EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(mdctx, buf, buf_size);
    EVP_DigestFinal_ex(mdctx, res, nullptr);
}

void optimizedMD5(std::vector<void*>& packets) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    auto* out = new unsigned char[MD5_DIGEST_LENGTH];
    for (const auto packet : packets) {
        calculate_md5_optimized(mdctx, packet, PACKET_SIZE, out);
        //printMD5(out);
    }
    EVP_MD_CTX_free(mdctx);
}

#include "md5-x86-asm.h"

template<typename HT>
void md5_init(MD5_STATE<HT>* state) {
	state->A = 0x67452301;
	state->B = 0xefcdab89;
	state->C = 0x98badcfe;
	state->D = 0x10325476;
}

template<typename HT, void(&fn)(MD5_STATE<HT>*, const void*)>
void md5(MD5_STATE<HT>* state, const void* __restrict__ src, size_t len) {
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

void externalMD5(std::vector<void*>& packets) {
    MD5_STATE<uint32_t> hash;
    for (const auto packet : packets) {
        // different optimizations
        //md5<uint32_t, md5_block_std>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_nolea>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_noleag>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_noleagh>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_cache4>(&hash, packet, PACKET_SIZE);
        //md5<uint32_t, md5_block_cache8>(&hash, packet, PACKET_SIZE);
        md5<uint32_t, md5_block_cache_gopt>(&hash, packet, PACKET_SIZE);
        //printMD5(reinterpret_cast<unsigned char*>(&hash));
    }
}

int main() {
    std::srand(time(0));
    std::vector<void*> packets;
    randomizePackets(packets);

    auto start = std::chrono::system_clock::now();
    unoptimizedMD5(packets);
    auto end = std::chrono::system_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Unoptimized snippet runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";

    start = std::chrono::system_clock::now();
    optimizedMD5(packets);
    end = std::chrono::system_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Optimized snippet runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";

    start = std::chrono::system_clock::now();
    externalMD5(packets);
    end = std::chrono::system_clock::now();
    elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start);
    std::cout << "Other library runtime (avg): " << elapsed.count() / static_cast<double>(packets.size()) << "ns \n";
}
