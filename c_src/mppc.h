/**
 * FreeRDP: A Remote Desktop Protocol Implementation
 * MPPC Bulk Data Compression
 *
 * Copyright 2014 Marc-Andre Moreau <marcandre.moreau@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef FREERDP_MPPC_H
#define FREERDP_MPPC_H

#include <stdint.h>

typedef enum {
        TRUE = 1,
        FALSE = 0
} BOOL;

typedef struct s_MPPC_CONTEXT MPPC_CONTEXT;

/* Level-2 Compression Flags */

#define PACKET_COMPRESSED 0x20
#define PACKET_AT_FRONT 0x40
#define PACKET_FLUSHED 0x80

/* Level-1 Compression Flags */

#define L1_PACKET_AT_FRONT 0x04
#define L1_NO_COMPRESSION 0x02
#define L1_COMPRESSED 0x01
#define L1_INNER_COMPRESSION 0x10

int mppc_compress(MPPC_CONTEXT* mppc, const uint8_t* pSrcData, uint32_t SrcSize,
                                uint8_t* pDstBuffer, const uint8_t** ppDstData, uint32_t* pDstSize,
                                uint32_t* pFlags);
int mppc_decompress(MPPC_CONTEXT* mppc, const uint8_t* pSrcData, uint32_t SrcSize,
                                  const uint8_t** ppDstData, uint32_t* pDstSize, uint32_t flags);

void mppc_set_compression_level(MPPC_CONTEXT* mppc, uint32_t CompressionLevel);

void mppc_context_reset(MPPC_CONTEXT* mppc, BOOL flush);

MPPC_CONTEXT* mppc_context_new(uint32_t CompressionLevel, BOOL Compressor);
void mppc_context_free(MPPC_CONTEXT* mppc);

#endif /* FREERDP_MPPC_H */
