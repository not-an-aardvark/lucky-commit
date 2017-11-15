#include <errno.h>
#include <math.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#define SHA1_SIZE 20

#define fail(...) fprintf(stderr, __VA_ARGS__); exit(1);

struct HashMatch {
  const uint8_t* data;
  const uint8_t* hash;
  size_t size;
};

struct HashMatchContainer {
  struct HashMatch match;
  pthread_mutex_t lock;
  pthread_cond_t done;
};

struct HashSearchParams {
  const char* const currentMessage;
  const char* const desiredPrefix;
  const uint64_t counterStart;
  const uint8_t extensionWordLength;
  struct HashMatchContainer* resultContainer;
};

struct ZlibResult {
  const uint8_t* data;
  unsigned long size;
};

/*
 * The 256 unique strings of length 8 which contain only ' ' and '\t'.
 * These are hardcoded so that commit padding strings can be generated with high
 * performance without needing to regenerate the padding one character at a time.
 *
 * This array was generated with the following Node.js script:
 * console.log(
 *   Array(256).fill()
 *     .map((_, index) => index.toString(2).padStart(8, '0').replace(/0/g, ' ').replace(/1/g, '\\t'))
 *     .map(str => `"${str}"`)
 *     .reduce(
 *       (str, value, index) =>
 *         str + value + (index % 4 === 3 ? ',\n  ' : ',' + ' '.repeat(18 - value.length)),
 *       ''
 *     )
 *   )
 */
static const char* const PADDINGS[] = {
  "        ",        "       \t",       "      \t ",       "      \t\t",
  "     \t  ",       "     \t \t",      "     \t\t ",      "     \t\t\t",
  "    \t   ",       "    \t  \t",      "    \t \t ",      "    \t \t\t",
  "    \t\t  ",      "    \t\t \t",     "    \t\t\t ",     "    \t\t\t\t",
  "   \t    ",       "   \t   \t",      "   \t  \t ",      "   \t  \t\t",
  "   \t \t  ",      "   \t \t \t",     "   \t \t\t ",     "   \t \t\t\t",
  "   \t\t   ",      "   \t\t  \t",     "   \t\t \t ",     "   \t\t \t\t",
  "   \t\t\t  ",     "   \t\t\t \t",    "   \t\t\t\t ",    "   \t\t\t\t\t",
  "  \t     ",       "  \t    \t",      "  \t   \t ",      "  \t   \t\t",
  "  \t  \t  ",      "  \t  \t \t",     "  \t  \t\t ",     "  \t  \t\t\t",
  "  \t \t   ",      "  \t \t  \t",     "  \t \t \t ",     "  \t \t \t\t",
  "  \t \t\t  ",     "  \t \t\t \t",    "  \t \t\t\t ",    "  \t \t\t\t\t",
  "  \t\t    ",      "  \t\t   \t",     "  \t\t  \t ",     "  \t\t  \t\t",
  "  \t\t \t  ",     "  \t\t \t \t",    "  \t\t \t\t ",    "  \t\t \t\t\t",
  "  \t\t\t   ",     "  \t\t\t  \t",    "  \t\t\t \t ",    "  \t\t\t \t\t",
  "  \t\t\t\t  ",    "  \t\t\t\t \t",   "  \t\t\t\t\t ",   "  \t\t\t\t\t\t",
  " \t      ",       " \t     \t",      " \t    \t ",      " \t    \t\t",
  " \t   \t  ",      " \t   \t \t",     " \t   \t\t ",     " \t   \t\t\t",
  " \t  \t   ",      " \t  \t  \t",     " \t  \t \t ",     " \t  \t \t\t",
  " \t  \t\t  ",     " \t  \t\t \t",    " \t  \t\t\t ",    " \t  \t\t\t\t",
  " \t \t    ",      " \t \t   \t",     " \t \t  \t ",     " \t \t  \t\t",
  " \t \t \t  ",     " \t \t \t \t",    " \t \t \t\t ",    " \t \t \t\t\t",
  " \t \t\t   ",     " \t \t\t  \t",    " \t \t\t \t ",    " \t \t\t \t\t",
  " \t \t\t\t  ",    " \t \t\t\t \t",   " \t \t\t\t\t ",   " \t \t\t\t\t\t",
  " \t\t     ",      " \t\t    \t",     " \t\t   \t ",     " \t\t   \t\t",
  " \t\t  \t  ",     " \t\t  \t \t",    " \t\t  \t\t ",    " \t\t  \t\t\t",
  " \t\t \t   ",     " \t\t \t  \t",    " \t\t \t \t ",    " \t\t \t \t\t",
  " \t\t \t\t  ",    " \t\t \t\t \t",   " \t\t \t\t\t ",   " \t\t \t\t\t\t",
  " \t\t\t    ",     " \t\t\t   \t",    " \t\t\t  \t ",    " \t\t\t  \t\t",
  " \t\t\t \t  ",    " \t\t\t \t \t",   " \t\t\t \t\t ",   " \t\t\t \t\t\t",
  " \t\t\t\t   ",    " \t\t\t\t  \t",   " \t\t\t\t \t ",   " \t\t\t\t \t\t",
  " \t\t\t\t\t  ",   " \t\t\t\t\t \t",  " \t\t\t\t\t\t ",  " \t\t\t\t\t\t\t",
  "\t       ",       "\t      \t",      "\t     \t ",      "\t     \t\t",
  "\t    \t  ",      "\t    \t \t",     "\t    \t\t ",     "\t    \t\t\t",
  "\t   \t   ",      "\t   \t  \t",     "\t   \t \t ",     "\t   \t \t\t",
  "\t   \t\t  ",     "\t   \t\t \t",    "\t   \t\t\t ",    "\t   \t\t\t\t",
  "\t  \t    ",      "\t  \t   \t",     "\t  \t  \t ",     "\t  \t  \t\t",
  "\t  \t \t  ",     "\t  \t \t \t",    "\t  \t \t\t ",    "\t  \t \t\t\t",
  "\t  \t\t   ",     "\t  \t\t  \t",    "\t  \t\t \t ",    "\t  \t\t \t\t",
  "\t  \t\t\t  ",    "\t  \t\t\t \t",   "\t  \t\t\t\t ",   "\t  \t\t\t\t\t",
  "\t \t     ",      "\t \t    \t",     "\t \t   \t ",     "\t \t   \t\t",
  "\t \t  \t  ",     "\t \t  \t \t",    "\t \t  \t\t ",    "\t \t  \t\t\t",
  "\t \t \t   ",     "\t \t \t  \t",    "\t \t \t \t ",    "\t \t \t \t\t",
  "\t \t \t\t  ",    "\t \t \t\t \t",   "\t \t \t\t\t ",   "\t \t \t\t\t\t",
  "\t \t\t    ",     "\t \t\t   \t",    "\t \t\t  \t ",    "\t \t\t  \t\t",
  "\t \t\t \t  ",    "\t \t\t \t \t",   "\t \t\t \t\t ",   "\t \t\t \t\t\t",
  "\t \t\t\t   ",    "\t \t\t\t  \t",   "\t \t\t\t \t ",   "\t \t\t\t \t\t",
  "\t \t\t\t\t  ",   "\t \t\t\t\t \t",  "\t \t\t\t\t\t ",  "\t \t\t\t\t\t\t",
  "\t\t      ",      "\t\t     \t",     "\t\t    \t ",     "\t\t    \t\t",
  "\t\t   \t  ",     "\t\t   \t \t",    "\t\t   \t\t ",    "\t\t   \t\t\t",
  "\t\t  \t   ",     "\t\t  \t  \t",    "\t\t  \t \t ",    "\t\t  \t \t\t",
  "\t\t  \t\t  ",    "\t\t  \t\t \t",   "\t\t  \t\t\t ",   "\t\t  \t\t\t\t",
  "\t\t \t    ",     "\t\t \t   \t",    "\t\t \t  \t ",    "\t\t \t  \t\t",
  "\t\t \t \t  ",    "\t\t \t \t \t",   "\t\t \t \t\t ",   "\t\t \t \t\t\t",
  "\t\t \t\t   ",    "\t\t \t\t  \t",   "\t\t \t\t \t ",   "\t\t \t\t \t\t",
  "\t\t \t\t\t  ",   "\t\t \t\t\t \t",  "\t\t \t\t\t\t ",  "\t\t \t\t\t\t\t",
  "\t\t\t     ",     "\t\t\t    \t",    "\t\t\t   \t ",    "\t\t\t   \t\t",
  "\t\t\t  \t  ",    "\t\t\t  \t \t",   "\t\t\t  \t\t ",   "\t\t\t  \t\t\t",
  "\t\t\t \t   ",    "\t\t\t \t  \t",   "\t\t\t \t \t ",   "\t\t\t \t \t\t",
  "\t\t\t \t\t  ",   "\t\t\t \t\t \t",  "\t\t\t \t\t\t ",  "\t\t\t \t\t\t\t",
  "\t\t\t\t    ",    "\t\t\t\t   \t",   "\t\t\t\t  \t ",   "\t\t\t\t  \t\t",
  "\t\t\t\t \t  ",   "\t\t\t\t \t \t",  "\t\t\t\t \t\t ",  "\t\t\t\t \t\t\t",
  "\t\t\t\t\t   ",   "\t\t\t\t\t  \t",  "\t\t\t\t\t \t ",  "\t\t\t\t\t \t\t",
  "\t\t\t\t\t\t  ",  "\t\t\t\t\t\t \t", "\t\t\t\t\t\t\t ", "\t\t\t\t\t\t\t\t",
};

static bool isValidPrefix(const char* const prefix) {
  if (strlen(prefix) > 40) {
    return false;
  }
  for (int i = 0; i < strlen(prefix); i++) {
    char currentChar = prefix[i];
    if (currentChar < '0' || (currentChar > '9' && currentChar < 'a') || currentChar > 'f') {
      return false;
    }
  }
  return true;
}

static const char* getCommandOutput(const char* const command) {
  FILE* pipe;
  char* output;
  uint32_t currentLength;
  const int chunkSize = 256;
  size_t bytesRead;

  pipe = popen(command, "r");

  if (pipe == NULL) {
    fprintf(stderr, "Failed to spawn '%s'\n", command);
    exit(1);
  }

  currentLength = 0;
  output = malloc(chunkSize);

  if (output == NULL) {
    fail("Failed to allocate output buffer for '%s'\n", command);
  }

  while ((bytesRead = fread(output + currentLength, 1, chunkSize, pipe)) == chunkSize) {
    currentLength += chunkSize;
    output = realloc(output, currentLength + chunkSize);
    if (output == NULL) {
      fail("Failed to allocate output buffer for '%s'\n", command);
    }
  }
  output[currentLength + bytesRead] = '\0';

  if (pclose(pipe) != 0) {
    fail("Command '%s' failed\n", command);
  }

  return output;
}

static const uint8_t* convertPrefix(const char* const prefix) {
  const size_t prefixLength = strlen(prefix);
  const uint8_t byteLength = (prefixLength + 1) / 2;
  uint8_t* const dataPrefix = malloc(byteLength);
  uint8_t dataOffset;
  uint8_t hexOffset;
  for (dataOffset = 0, hexOffset = 0; hexOffset < prefixLength - 1; dataOffset++, hexOffset += 2) {
    sscanf(prefix + hexOffset, "%2hhx", &dataPrefix[dataOffset]);
  }
  if (hexOffset == prefixLength - 1) {
    sscanf(prefix + hexOffset, "%1hhx", &dataPrefix[dataOffset]);
    dataPrefix[dataOffset] <<= 4;
  }
  return dataPrefix;
}

static bool matchesPrefix(
  const uint8_t* const hash,
  const uint8_t* const dataPrefix,
  const size_t dataPrefixLength,
  const bool hasOddChar
) {
  return memcmp(hash, dataPrefix, dataPrefixLength) == 0 &&
    (
      !hasOddChar ||
      dataPrefix[dataPrefixLength] == (hash[dataPrefixLength] & 0xf0)
    );
}

static size_t numDigits(const size_t value) {
  return (size_t)log10(value) + 1;
}

static size_t getStartIndexOfLine(const char* message, const size_t desiredLine) {
  const char* cursor;
  size_t lineNum = 0;
  for (cursor = message; lineNum < desiredLine; cursor++) {
    switch (*cursor) {
      case '\n':
        lineNum++;
        break;
      case '\0':
        return cursor - message;
    }
  }
  return cursor - message;
}

static size_t getSplitIndex(const char* const commitMessage) {
  /*
   * If the commit has a GPG signature (detected by the presence of "gpgsig " at the start
   * of the fifth line), then add the padding whitespace immediately after the text "gpgsig ".
   * Otherwise, add the padding whitespace right before the end of the commit message.
   *
   * If a signature is present, modifying the commit message would make the signature invalid.
   */
  const size_t fifthLineStartIndex = getStartIndexOfLine(commitMessage, 4);
  const char* const fifthLine = commitMessage + fifthLineStartIndex;
  const char* const marker = "gpgsig ";

  if (memcmp(fifthLine, marker, strlen(marker)) == 0) {
    return fifthLineStartIndex + strlen(marker);
  } else {
    return strlen(commitMessage) - 1;
  }
}

static void* getMatch(void* const params) {
  const struct HashSearchParams* searchParams = (struct HashSearchParams*)params;
  const char* const currentMessage = searchParams->currentMessage;
  const char* const desiredPrefix = searchParams->desiredPrefix;
  const uint8_t extensionLength = searchParams->extensionWordLength * 8;

  const size_t initialMessageLength = strlen(currentMessage);
  const size_t headerLength = strlen("commit ") + numDigits(initialMessageLength) + 1;
  const size_t messageLength = initialMessageLength + extensionLength;
  const size_t dataLength = headerLength + messageLength;

  uint8_t* const messageData = malloc(dataLength + 1);
  const size_t splitIndex = getSplitIndex(currentMessage);
  uint8_t* const padding = messageData + headerLength + splitIndex;;

  uint8_t* const hash = malloc(SHA1_SIZE);

  const uint8_t* const dataPrefix = convertPrefix(desiredPrefix);
  const size_t dataPrefixLength = strlen(desiredPrefix) / 2;
  const bool hasOddChar = strlen(desiredPrefix) % 2 == 1;

  uint64_t counter = searchParams->counterStart;

  if (messageData == NULL) {
    fail("Failed to allocate a new commit message\n");
  }

  if (currentMessage[initialMessageLength - 1] != '\n') {
    fail("Error: expected the current commit message to end in a newline\n");
  }

  sprintf((char*)messageData, "commit %zu", messageLength);
  memcpy(messageData + headerLength, currentMessage, splitIndex);
  memcpy(
    messageData + headerLength + splitIndex + extensionLength,
    currentMessage + splitIndex,
    initialMessageLength - splitIndex + 1
  );

  do {
    for (uint8_t blockOffset = 0; blockOffset < extensionLength; blockOffset += 8) {
      memcpy(padding + blockOffset, PADDINGS[(counter >> blockOffset) & 0xff], 8);
    }
    SHA1(messageData, dataLength, hash);
    counter++;
  } while (!matchesPrefix(hash, dataPrefix, dataPrefixLength, hasOddChar));

  struct HashMatchContainer* const resultContainer = searchParams->resultContainer;

  pthread_mutex_lock(&resultContainer->lock);

  resultContainer->match.data = messageData;
  resultContainer->match.hash = hash;
  resultContainer->match.size = dataLength;

  pthread_cond_signal(&resultContainer->done);
  pthread_mutex_unlock(&resultContainer->lock);

  return NULL;
}

static const struct ZlibResult* compressObject(const uint8_t* const data, const size_t size) {
  size_t outputSize = 2 * size;
  uint8_t* const output = malloc(outputSize);

  z_stream deflateStream = (z_stream){
    .zalloc = Z_NULL,
    .zfree = Z_NULL,
    .opaque = Z_NULL,
    .avail_in = size,
    .next_in = (uint8_t*)data,
    .avail_out = outputSize,
    .next_out = output
  };

  deflateInit(&deflateStream, Z_DEFAULT_COMPRESSION);
  deflate(&deflateStream, Z_FINISH);
  deflateEnd(&deflateStream);

  struct ZlibResult* const result = malloc(sizeof(struct ZlibResult));
  result->data = realloc(output, deflateStream.total_out);
  result->size = deflateStream.total_out;

  return result;
}

static void writeGitObject(const uint8_t* const hash, const struct ZlibResult* const object) {
  char dirName[strlen(".git/objects/") + 3];
  char fileName[strlen(".git/objects/") + SHA1_SIZE * 2 + 2];

  sprintf(dirName, ".git/objects/%02x", hash[0]);
  sprintf(fileName, "%s/", dirName);

  uint8_t hashIndex;
  size_t stringOffset;

  for (hashIndex = 1, stringOffset = strlen(fileName); hashIndex < SHA1_SIZE; hashIndex++, stringOffset += 2) {
    sprintf(fileName + stringOffset, "%02x", hash[hashIndex]);
  }

  if (mkdir(dirName, 755) != 0 && errno != EEXIST) {
    fail("Failed to create %s directory\n", dirName);
  }

  FILE* const file = fopen(fileName, "w");
  if (file == NULL) {
    fail("Failed to open %s\n", fileName);
  }

  if (fwrite(object->data, 1, object->size, file) != object->size) {
    fclose(file);
    fail("Failed to write to %s\n", fileName);
  }
  fclose(file);
}

static void gitResetToHash(const uint8_t* const hash) {
  char command[strlen("git reset ") + SHA1_SIZE * 2 + 1];
  sprintf(command, "git reset ");

  uint8_t hashIndex;
  size_t stringOffset;

  for (hashIndex = 0, stringOffset = strlen(command); hashIndex < SHA1_SIZE; hashIndex++, stringOffset += 2) {
    sprintf(command + stringOffset, "%02x", hash[hashIndex]);
  }

  getCommandOutput(command);
}

static void luckyCommit(char* desiredPrefix) {
  const char* const currentCommit = getCommandOutput("git cat-file commit HEAD");

  const size_t NUM_THREADS = sysconf(_SC_NPROCESSORS_ONLN);
  pthread_t threads[NUM_THREADS];
  struct HashSearchParams params[NUM_THREADS];
  struct HashMatchContainer result;

  pthread_mutex_init(&result.lock, NULL);
  pthread_cond_init(&result.done, NULL);

  pthread_mutex_lock(&result.lock);
  for (size_t i = 0; i < NUM_THREADS; i++) {
    params[i] = (struct HashSearchParams){
      .currentMessage = currentCommit,
      .desiredPrefix = desiredPrefix,
      .counterStart = (1UL << 63) / NUM_THREADS * i * 2,
      .extensionWordLength = 8,
      .resultContainer = &result
    };
    if (pthread_create(&threads[i], NULL, getMatch, &params[i]) != 0) {
      fail("Failed to create pthread for hash searching\n");
    }
  }

  pthread_cond_wait(&result.done, &result.lock);

  const struct ZlibResult* const compressedObject = compressObject(result.match.data, result.match.size);

  writeGitObject(result.match.hash, compressedObject);
  gitResetToHash(result.match.hash);
}

int main(const int argc, char** const argv) {
  if (argc == 1) {
    luckyCommit("0000000");
  } else if (argc == 2 && isValidPrefix(argv[1])) {
    luckyCommit(argv[1]);
  } else {
    fail("Usage: lucky-commit [commit-hash-prefix]\n");
  }

  return 0;
}
