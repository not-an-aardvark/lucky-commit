#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <zlib.h>

#define SHA1_SIZE 20
#define EXTENSION_LENGTH 64

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
const char* PADDINGS[] = {
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

void fail(char* errorMessage) {
  fprintf(stderr, "%s", errorMessage);
  exit(1);
}

char* readFile(char* filename) {
  FILE* file;
  uint64_t size;
  char* buffer;

  file = fopen(filename, "r");

  if (file == NULL) {
    fail("Failed to open file\n");
  }

  fseek(file, 0L, SEEK_END);

  size = ftell(file);
  rewind(file);

  buffer = malloc(size + 1);
  buffer[size] = '\0';

  if (buffer == NULL || fread(buffer, size, 1, file) != 1) {
    fclose(file);
    fail("Failed to read file\n");
  }

  fclose(file);

  return buffer;
}

bool isValidPrefix(char* prefix) {
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

char* getCommandOutput(char* command) {
  FILE* pipe;
  char* output;
  uint32_t currentLength;
  const int chunkSize = 8;
  size_t bytesRead;

  pipe = popen(command, "r");

  if (pipe == NULL) {
    fprintf(stderr, "Failed to spawn git process\n");
    exit(1);
  }

  currentLength = 0;
  output = malloc(chunkSize);

  if (output == NULL) {
    fail("Failed to allocate output buffer\n");
  }

  while ((bytesRead = fread(output + currentLength, 1, chunkSize, pipe)) == chunkSize) {
    currentLength += chunkSize;
    output = realloc(output, currentLength + chunkSize);
    if (output == NULL) {
      fail("Failed to allocate output buffer\n");
    }
  }
  output[currentLength + bytesRead] = '\0';

  if (pclose(pipe) != 0) {
    fail("Git command failed\n");
  }

  return output;
}

unsigned char* convertPrefix(char* prefix) {
  size_t prefixLength = strlen(prefix);
  uint8_t byteLength = (prefixLength + 1) / 2;
  unsigned char* dataPrefix = malloc(byteLength);
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

bool matchesPrefix(unsigned char* hash, unsigned char* dataPrefix, size_t dataPrefixLength, bool hasOddChar) {
  return memcmp(hash, dataPrefix, dataPrefixLength) == 0 &&
    (
      !hasOddChar ||
      dataPrefix[dataPrefixLength] == (hash[dataPrefixLength] & 0xf0)
    );
}

size_t numDigits(size_t value) {
  return (size_t)log10(value) + 1;
}

size_t getStartIndexOfLine(const char* message, const size_t desiredLine) {
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

size_t getSplitIndex(const char* commitMessage) {
  /*
   * If the commit has a GPG signature (detected by the presence of "gpgsig " at the start
   * of the fifth line), then add the padding whitespace immediately after the text "gpgsig ".
   * Otherwise, add the padding whitespace right before the end of the commit message.
   *
   * If a signature is present, modifying the commit message would make the signature invalid.
   */
  const size_t fifthLineStartIndex = getStartIndexOfLine(commitMessage, 4);
  const char* fifthLine = commitMessage + fifthLineStartIndex;
  const char* marker = "gpgsig ";

  if (memcmp(fifthLine, marker, strlen(marker)) == 0) {
    return fifthLineStartIndex + strlen(marker);
  } else {
    return strlen(commitMessage) - 1;
  }
}

struct HashMatch {
  char* data;
  unsigned char* hash;
  size_t size;
};

struct HashMatch* getMatch(char* currentMessage, char* desiredPrefix) {
  const size_t initialMessageLength = strlen(currentMessage);
  const size_t headerLength = strlen("commit ") + numDigits(initialMessageLength) + 1;
  const size_t messageLength = initialMessageLength + EXTENSION_LENGTH;
  const size_t dataLength = headerLength + messageLength;
  char* messageData = malloc(dataLength + 1);
  char* padding;
  unsigned char* hash = malloc(SHA1_SIZE);
  unsigned char* dataPrefix = convertPrefix(desiredPrefix);
  const size_t dataPrefixLength = strlen(desiredPrefix) / 2;
  const bool hasOddChar = strlen(desiredPrefix) % 2 == 1;
  const size_t splitIndex = getSplitIndex(currentMessage);

  if (messageData == NULL) {
    fail("Failed to allocate a new commit message\n");
  }

  if (currentMessage[initialMessageLength - 1] != '\n') {
    fail("Error: expected the current commit message to end in a newline\n");
  }

  sprintf(messageData, "commit %zu", messageLength);
  memcpy(messageData + headerLength, currentMessage, splitIndex);
  memcpy(
    messageData + headerLength + splitIndex + EXTENSION_LENGTH,
    currentMessage + splitIndex,
    initialMessageLength - splitIndex + 1
  );
  padding = messageData + headerLength + splitIndex;

  uint64_t counter = 0;

  do {
    for (uint8_t blockOffset = 0; blockOffset < EXTENSION_LENGTH; blockOffset += 8) {
      memcpy(padding + blockOffset, PADDINGS[(counter >> blockOffset) & 0xff], 8);
    }
    SHA1((unsigned char*)messageData, dataLength, hash);
    counter++;
  } while (!matchesPrefix(hash, dataPrefix, dataPrefixLength, hasOddChar));

  struct HashMatch* match = malloc(sizeof(struct HashMatch));
  match->data = messageData;
  match->hash = hash;
  match->size = dataLength;

  return match;
}

struct ZlibResult {
  unsigned char* data;
  unsigned long size;
};

struct ZlibResult* compressObject(unsigned char* data, size_t size) {
  z_stream deflateStream;
  size_t outputSize = 2 * size;
  unsigned char* output = malloc(outputSize);

  deflateStream.zalloc = Z_NULL;
  deflateStream.zfree = Z_NULL;
  deflateStream.opaque = Z_NULL;
  deflateStream.avail_in = size;
  deflateStream.next_in = data;
  deflateStream.avail_out = outputSize;
  deflateStream.next_out = output;

  deflateInit(&deflateStream, Z_DEFAULT_COMPRESSION);
  deflate(&deflateStream, Z_FINISH);
  deflateEnd(&deflateStream);

  struct ZlibResult* result = malloc(sizeof(struct ZlibResult));
  result->data = realloc(output, deflateStream.total_out);
  result->size = deflateStream.total_out;

  return result;
}

void writeGitObject(unsigned char* hash, struct ZlibResult* object) {
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
    fail("Failed to create .git/objects/xx directory\n");
  }

  FILE* file = fopen(fileName, "w");
  if (file == NULL) {
    fail("Failed to open git object file\n");
  }

  if (fwrite(object->data, 1, object->size, file) != object->size) {
    fclose(file);
    fail("Failed to write git object file\n");
  }
  fclose(file);
}

void gitResetToHash(unsigned char* hash) {
  char command[strlen("git reset ") + SHA1_SIZE * 2 + 1];
  sprintf(command, "git reset ");

  uint8_t hashIndex;
  size_t stringOffset;

  for (hashIndex = 0, stringOffset = strlen(command); hashIndex < SHA1_SIZE; hashIndex++, stringOffset += 2) {
    sprintf(command + stringOffset, "%02x", hash[hashIndex]);
  }

  getCommandOutput(command);
}

void luckyCommit(char* desiredPrefix) {
  char* currentCommit = getCommandOutput("git cat-file commit HEAD");

  struct HashMatch* match = getMatch(currentCommit, desiredPrefix);
  struct ZlibResult* compressedObject = compressObject((unsigned char*)match->data, match->size);

  writeGitObject(match->hash, compressedObject);
  gitResetToHash(match->hash);
}

int main(int argc, char** argv) {
  if (argc == 1) {
    luckyCommit("0000000");
  } else if (argc == 2 && isValidPrefix(argv[1])) {
    luckyCommit(argv[1]);
  } else {
    fail("Usage: lucky-commit [commit-hash-prefix]\n");
  }

  return 0;
}
