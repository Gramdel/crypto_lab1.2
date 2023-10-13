#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

// Функция для вывода сообщения об ошибке в аргументах командной строки
void show_arg_err(const char* arg) {
    if (arg == NULL) {
        printf("Invalid number of arguments! Use \"-h\" or \"--help\" for help.\n");
    } else {
        printf("Invalid arguments: \"%s\"! Use \"-h\" or \"--help\" for help.\n", arg);
    }
}

// Функция для вывода сообщения об ошибке при открытии файла
void show_file_err(const char* filename) {
    printf("Could not open file \"%s\"!\n", filename);
}

// Функция для вывода справки
void show_help() {
    printf("Usage:\n");
    printf("\t-d <file> -k <key>\n");
    printf("\t\tTakes contents of the file and decodes them using IDEA cipher.\n");
    printf("\t\tKey needs to be a 128-bit (16 characters) string.\n");
    printf("\t\tDecoded file will be called \"decoded_<file>\".\n");
    printf("\t-e <file> -k <key>\n");
    printf("\t\tTakes contents of the file and encodes them using IDEA cipher.\n");
    printf("\t\tKey needs to be a 128-bit (16 characters) string.\n");
    printf("\t\tEncoded file will be called \"encoded_<file>\".\n");
    printf("\t-h, --help\n");
    printf("\t\tDisplays this message.\n");
}

// Умножение по модулю 2^16+1, причем блок из 16 нулей рассматривается как 2^16
uint16_t mul(uint16_t a, uint16_t b) {
    return ((uint32_t) ((a == 0 ? 0x10000 : a) * (b == 0 ? 0x10000 : b)) % 0x10001);
}

// Нахождение аддитивной (-x) обратной величины
uint16_t reverse_add(uint16_t x) {
    return (0x10000 - x);
}

// Нахождение мультипликативной (1/x) обратной величины (от 0 равна 0)
uint16_t reverse_mul(uint16_t x) {
    uint64_t n = 0x10000 - 1;
    uint64_t a = (uint64_t) x;
    uint64_t r = 1;
    while (n) {
        if (n & 1) r = (r * a) % 0x10001;
        n >>= 1;
        a = (a * a) % 0x10001;
    }
    return r;
}


// Функция для генерации подключей
void generate_subkeys(const char* key, uint16_t* subkeys) {
    // Записываем первые 8 подключей
    for (size_t i = 0; i < 8; i++) {
        subkeys[i] = (key[i * 2] << 8) | key[i * 2 + 1];
    }

    // Записываем оставшиеся подключи (каждый ключ получается на основе ключа с предыдущего шага)
    uint16_t upper, lower;
    for (size_t i = 8; i < 6 * 8 + 4; i++) {
        // Если i+1 или i+2 выходят за границы, нужно брать элементы из начала (=продвинуться глубже)
        upper = subkeys[(i + 1) % 8 == 0 ? i - 15 : i - 7] << 9;
        lower = subkeys[(i + 2) % 8 < 2 ? i - 14 : i - 6] >> 7;
        subkeys[i] = upper | lower;
    }
}

// Функция для генерации обратных подключей
void generate_reverse_subkeys(const uint16_t* subkeys, uint16_t* reverse_subkeys) {
    // Идем по строкам
    for (size_t i = 0; i < 9; i++) {
        uint8_t s = i % 8 == 0; // в первой и последней строках ключи 2 и 3 не поменяны местами
        // Заполняем первые 4 ключа в строке
        reverse_subkeys[i * 6 + 0] = reverse_mul(subkeys[(8 - i) * 6 + 0]);
        reverse_subkeys[i * 6 + 1] = reverse_add(subkeys[(8 - i) * 6 + 2 - s]);
        reverse_subkeys[i * 6 + 2] = reverse_add(subkeys[(8 - i) * 6 + 1 + s]);
        reverse_subkeys[i * 6 + 3] = reverse_mul(subkeys[(8 - i) * 6 + 3]);
        // Заполняем 5 и 6 ключи (кроме последней строки):
        if (i != 8) {
            reverse_subkeys[i * 6 + 4] = subkeys[(7 - i) * 6 + 4];
            reverse_subkeys[i * 6 + 5] = subkeys[(7 - i) * 6 + 5];
        }
    }
}

// Функция для шифрования одного блока данных
void idea_encrypt_block(const uint16_t* subkeys, const uint8_t* block, uint8_t* new_block) {
    // Получаем субблоки
    uint16_t x[4];
    for (size_t i = 0; i < 4; i++) {
        x[i] = block[i * 2] << 8 | block[i * 2 + 1];
    }

    // Выполняем 8 раундов
    uint16_t step[14];
    for (size_t i = 0; i < 8; i++) {
        // Выполняем 14 шагов
        step[0] = mul(x[0], subkeys[6 * i]);        //  1. умножение субблока X1 и первого подключа
        step[1] = x[1] + subkeys[6 * i + 1];             //  2. сложение субблока X2 и второго подключа
        step[2] = x[2] + subkeys[6 * i + 2];             //  3. сложение субблока X3 и третьего подключа
        step[3] = mul(x[3], subkeys[6 * i + 3]);    //  4. умножение субблока X4 и четвертого подключа
        step[4] = step[0] ^ step[2];                     //  5. сложение (по модулю 2) результатов шагов 1 и 3
        step[5] = step[1] ^ step[3];                     //  6. сложение (по модулю 2) результатов шагов 2 и 4
        step[6] = mul(step[4], subkeys[6 * i + 4]); //  7. умножение результата шага 5 и пятого подключа
        step[7] = step[5] + step[6];                     //  8. сложение результатов шагов 6 и 7
        step[8] = mul(step[7], subkeys[6 * i + 5]); //  9. умножение результата шага 8 и шестого подключа
        step[9] = step[6] + step[8];                     // 10. сложение результатов шагов 7 и 9
        x[0] = step[10] = step[0] ^ step[8];             // 11. сложение (по модулю 2) результатов шагов 1 и 9
        x[1] = step[11] = step[2] ^ step[8];             // 12. сложение (по модулю 2) результатов шагов 3 и 9
        x[2] = step[12] = step[1] ^ step[9];             // 13. сложение (по модулю 2) результатов шагов 2 и 10
        x[3] = step[13] = step[3] ^ step[9];             // 14. сложение (по модулю 2) результатов шагов 4 и 10
    }

    // Заключительное преобразование
    x[0] = mul(x[0], subkeys[6 * 8]);     // 1. умножение субблока X1 и первого подключа
    x[1] = step[12] + subkeys[6 * 8 + 1];      // 2. сложение субблока X2 и второго подключа
    x[2] = step[11] + subkeys[6 * 8 + 2];      // 3. сложение субблока X3 и третьего подключа
    x[3] = mul(x[3], subkeys[6 * 8 + 3]); // 4. умножение субблока X4 и четвертого подключа

    // Заполняем новый блок
    for (size_t i = 0; i < 4; i++) {
        new_block[i * 2] = x[i] >> 8;
        new_block[i * 2 + 1] = x[i];
    }
}

// Функция для шифрования данных (IDEA + PCBC)
void encrypt(const char* input_file, char* key, bool decrypt) {
    //uint8_t k[16] = { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08 };
    //uint8_t block[8] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03 };
    uint16_t subkeys[6 * 8 + 4], reverse_subkeys[6 * 8 + 4];
    generate_subkeys(key, subkeys);
    if (decrypt) {
        generate_reverse_subkeys(subkeys, reverse_subkeys);
    }

    char output_file[strlen(input_file) + 8];
    sprintf(output_file, "%s%s", decrypt ? "decoded_" : "encoded_", input_file); // Выбор имени выходного файла

    FILE* fin = fopen(input_file, "rb");
    if (!fin) {
        show_file_err(input_file);
        return;
    }

    FILE* fout = fopen(output_file, "wb");
    if (!fout) {
        show_file_err(output_file);
        fclose(fin);
        return;
    }

    uint8_t prev_data[8], data[8], prev_block[8], block[8];
    memset(prev_data, 0, 8); // заполняем IV нулями
    memset(prev_block, 0, 8); // заполняем IV нулями

    while (1) {
        size_t read_bytes = fread(data, sizeof(uint8_t), 8, fin);
        if (read_bytes == 0) {
            printf("Success! Check file \"%s\"", output_file);
            break;
        }
        // Если не хватает байтов до 8, дополняем нулями
        if (read_bytes < 8) {
            memset(data + read_bytes, 0, 8 - read_bytes);
        }

        if (decrypt) {
            idea_encrypt_block(reverse_subkeys, data, block);
            for (int i = 0; i < 8; i++) {
                block[i] ^= prev_data[i] ^ prev_block[i];
            }
        } else {
            for (int i = 0; i < 8; i++) {
                data[i] ^= prev_data[i] ^ prev_block[i];
            }
            idea_encrypt_block(subkeys, data, block);
        }
        memcpy(prev_data, data, 8);
        memcpy(prev_block, block, 8);
        fwrite(block, sizeof(uint8_t), 8, fout);
    }

    fclose(fin);
    fclose(fout);
}

int main(int argc, char* argv[]) {
    if (argc == 2) { // Ловим -h и --help
        if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            show_help();
        } else {
            show_arg_err(argv[1]);
        }
    } else if (argc == 5) { // Ловим -d и -e
        if ((strcmp(argv[1], "-d") != 0 && strcmp(argv[1], "-e") != 0) || strcmp(argv[3], "-k") != 0 ||
            strlen(argv[4]) != 16) {
            show_arg_err(argv[1]);
        } else {
            encrypt(argv[2], argv[4], strcmp(argv[1], "-d") == 0);
        }
    } else {
        show_arg_err(NULL);
    }
    return 0;
}