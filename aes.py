from typing import List
import os
from PIL import Image
import exifread
import matplotlib.pyplot as plt
import numpy as np
import hashlib

# Declaração da matriz SBOX e RCON
# SBOX é uma tabela de substituição usada no AES para a operação de substituição de bytes
SBOX = [
   0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
   0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
   0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
   0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
   0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
   0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
   0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
   0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
   0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
   0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
   0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
   0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
   0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
   0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
   0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
   0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
]

# RCON é uma tabela de constantes usadas no AES para a operação de expansão de chave

RCON = [
    0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80,
    0x1B, 0x36, 0x6c, 0xd8,  # Extended RCON values
    0xab, 0x4d, 0x9a, 0x2f,
    0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4,
    0xb3, 0x7d, 0xfa, 0xef,
    0xc5, 0x91
]

# INV_S_BOX é a tabela inversa de SBOX, usada para a operação de substituição de bytes na decriptação

INV_S_BOX = [0] * 256
for i in range(256):
    INV_S_BOX[SBOX[i]] = i

def xtime(a):
    if a & 0x80:
        return ((a<<1)^0x1B) & 0xFF
    else:
        return a << 1

MUL2 = [xtime(i) for i in range(256)]
MUL3 = [MUL2[i] ^ i for i in range(256)]

# Função para separar os metadados EXIF e os dados de pixel da imagem JPG

def separa_exif_e_dados_pixel(caminho_arquivo):
    try:
        with open(caminho_arquivo, 'rb') as f:
            imagem_bytes = f.read()
            tags = exifread.process_file(f, stop_tag='APP0') # Lê apenas os headers iniciais
            f.seek(0)

            sos_marcador = b'\xff\xda'
            sos_index = imagem_bytes.find(sos_marcador)
            if sos_index != -1:
                metadados = imagem_bytes[:sos_index + len(sos_marcador)]
                dados_pixel = imagem_bytes[sos_index + len(sos_marcador):]
                return metadados, dados_pixel
    except FileNotFoundError:
        print(f"Erro: Arquivo não encontrado em {caminho_arquivo}")
    except Exception as e:
        print(f"Ocorreu um erro: {e}")

# Função para salvar a imagem com os metadados EXIF e os dados de pixel

def salva_imagem_com_exif(caminho_arquivo, metadados, dados_pixel):
    try:
        with open(caminho_arquivo, 'wb') as f:
            imagem_bytes = metadados + dados_pixel
            f.write(imagem_bytes)
            print(f"imagem salva em: {caminho_arquivo}")
    except Exception as e:
        print(f"Ocorreu um erro ao salvar a imagem: {e}")

# Função para recuperar os dados RGB da imagem usando Pillow

def recupera_rgb_de_pillow(caminho_arquivo):
    try:
        img = Image.open(caminho_arquivo)
        img_rgb = img.convert('RGB')
        return img_rgb
    except Exception as e:
        print(f"Ocorreu um erro ao recuperar os dados RGB: {e}")
        return None

# Função para converter um array RGB em uma imagem e salvá-la

def converte_array_para_imagem(array_rgb, caminho_arquivo_salvo):
    try:
        img = Image.fromarray(array_rgb, 'RGB')
        img.save(caminho_arquivo_salvo)
        img.show()
    except Exception as e:
        print(f"Ocorreu um erro ao converter o array para imagem: {e}")

# Função para gerar o hash SHA-256 de um dado

def gera_hash_sha256(dados):
    sha256 = hashlib.sha256()
    sha256.update(dados)
    return sha256.hexdigest()

# Função para gerar o hash SHA-256 de um arquivo

def gera_hash_arquivo(caminho_arquivo):
    hasher = hashlib.sha256()
    with open(caminho_arquivo, 'rb') as f:
        while True:
            lote = f.read(4096)  # Read in chunks of 4KB
            if not lote:
                break
            hasher.update(lote)
    return hasher.hexdigest()

# Implementação da classe MyAES para criptografia e descriptografia AES
# Esta classe implementa o algoritmo AES, incluindo as operações de substituição 
# de bytes, mistura de colunas, etc. Implementa também os modos de operação ECB e CTR.

class MyAES:
    def __init__(self, chave, nonce, iv):
        self.chave = chave
        self.nonce = nonce
        self.bloco_size = 16
        self.iv = iv

    # Método para substituir os bytes do estado usando a SBOX

    def sub_bytes(self, estado):
        sub_byte = []
        for b in estado:
            sub_byte.append(SBOX[b])
        return sub_byte

    # Método para realizar a operação de deslocamento de linhas

    def shift_linhas(self, s):
        return [
            s[0], s[5], s[10], s[15],
            s[4], s[9], s[14], s[3],
            s[8], s[13], s[2], s[7],
            s[12], s[1], s[6], s[11]
        ]

    # Método para misturar os bytes de uma única coluna

    def mistura_unica_coluna(self, col):
        return [
            MUL2[col[0]] ^ MUL3[col[1]] ^ col[2] ^ col[3],
            col[0] ^ MUL2[col[1]] ^ MUL3[col[2]] ^ col[3],
            col[0] ^ col[1] ^ MUL2[col[2]] ^ MUL3[col[3]],
            MUL3[col[0]] ^ col[1] ^ col[2] ^ MUL2[col[3]]
        ]

    # Método para misturar as colunas do estado

    def mistura_colunas(self, estado):
        misturadas_colunas = []
        for i in range(0, 16,4):
            misturadas_colunas.append(self.mistura_unica_coluna(estado[i:i+4]))
        return [byte for col in misturadas_colunas for byte in col]

    # Método para adicionar a chave de rodada ao estado
    
    def adiciona_round_chave(self, estado, round_chave):
        resultado_chave = []
        for b, k in zip(estado, round_chave):
            resultado_chave.append(b^k)
        return resultado_chave

    # Método para expandir a chave original em várias chaves de rodada

    def chave_expansion(self, chave, round=10):
        chave_simbolos = chave
        chave_schedule = list(chave_simbolos)
        chave_resultado = []
        # Change the range to generate enough subkeys for the specified number of rounds
        for i in range(4, 4 * (round + 1) + 4):  # round + 1 for the initial round + round for the main rounds
            temp = chave_schedule[(i - 1) * 4:i * 4]
            if i % 4 == 0:
                temp = [SBOX[temp[1]] ^ RCON[i // 4 - 1], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            palavra = []
            for a, b in zip(chave_schedule[(i - 4) * 4:(i - 3) * 4], temp):
                palavra.append(a ^ b)
            chave_schedule.extend(palavra)

        num_subkeys = round + 1
        for i in range(0, num_subkeys * 16, 16):
            chave_resultado.append(chave_schedule[i:i + 16])

        return chave_resultado

    # Método para criptografar um bloco de 16 bytes usando AES

    def aes_encriptar_bloco(self, texto_claro, chave, round=10):
        estado = list(texto_claro)
        round_chaves = self.chave_expansion(chave, round)
        estado = self.adiciona_round_chave(estado, round_chaves[0])
        for i in range(1, round):
            estado = self.sub_bytes(estado)
            estado = self.shift_linhas(estado)
            estado = self.mistura_colunas(estado)
            estado = self.adiciona_round_chave(estado, round_chaves[i])
        estado = self.sub_bytes(estado)
        estado = self.shift_linhas(estado)
        estado = self.adiciona_round_chave(estado, round_chaves[round])

        return estado

    # Método para adicionar padding ao texto_claro para que seu tamanho seja múltiplo de 16

    def pad(self, texto_claro):
        padicionaing_len = 16 - (len(texto_claro)%16)
        return texto_claro + bytes([padicionaing_len] * padicionaing_len)

    # Método para remover o padding do texto_claro

    def unpad(self, padicionaed):
        pad_len = padicionaed[-1]
        if padicionaed[-pad_len:] != bytes([pad_len]*pad_len):
            raise ValueError("Padding inválido")
        return padicionaed[:-pad_len]

    # Método para inverter a operação de substituição de bytes

    def inv_sub_bytes(self, estado):
        inv_bytes = []
        for b in estado:
            inv_bytes.append(INV_S_BOX[b])
        return inv_bytes

    # Método para inverter a operação de deslocamento de linhas

    def inv_shift_linhas(self, s):
        return [
            s[0], s[13], s[10], s[7],
            s[4], s[1], s[14], s[11],
            s[8], s[5], s[2], s[15],
            s[12], s[9], s[6], s[3]
        ]

    # Método para realizar a multiplicação em GF(2^8)

    def mul(self, a, b):
        p = 0
        for i in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit:
                a ^= 0x1B
            b >>= 1
        return p & 0xFF

    # Método para inverter a mistura de uma única coluna

    def inv_mistura_unica_coluna(self, col):
        return [
            self.mul(col[0], 0x0e) ^ self.mul(col[1], 0x0b) ^ self.mul(col[2], 0x0d) ^ self.mul(col[3], 0x09),
            self.mul(col[0], 0x09) ^ self.mul(col[1], 0x0e) ^ self.mul(col[2], 0x0b) ^ self.mul(col[3], 0x0d),
            self.mul(col[0], 0x0d) ^ self.mul(col[1], 0x09) ^ self.mul(col[2], 0x0e) ^ self.mul(col[3], 0x0b),
            self.mul(col[0], 0x0b) ^ self.mul(col[1], 0x0d) ^ self.mul(col[2], 0x09) ^ self.mul(col[3], 0x0e)
        ]

    # Método para inverter a mistura de colunas do estado

    def inv_mistura_colunas(self, estado):
        return sum([self.inv_mistura_unica_coluna(estado[i:i+4]) for i in range(0, 16, 4)], [])

    # Método para decriptografar um bloco de 16 bytes usando AES

    def aes_decriptar_bloco(self, texto_cifrado, chave, round=10):
        estado = list(texto_cifrado)
        round_chaves = self.chave_expansion(chave, round)
        estado = self.adiciona_round_chave(estado, round_chaves[round])
        estado = self.inv_shift_linhas(estado)
        estado = self.inv_sub_bytes(estado)

        for i in range(round-1, 0 ,-1):
            estado = self.adiciona_round_chave(estado, round_chaves[i])
            estado = self.inv_mistura_colunas(estado)
            estado = self.inv_shift_linhas(estado)
            estado = self.inv_sub_bytes(estado)

        estado = self.adiciona_round_chave(estado, round_chaves[0])
        return estado

    # Método para criptografar os dados usando o modo ECB

    def aes_encriptar_ecb(self, data, chave, round=10):
        data = self.pad(data)
        resultado = b''
        for i in range(0, len(data), 16):
            bloco = list(data[i:i+16])
            encriptado = self.aes_encriptar_bloco(bloco, chave, round)
            resultado += bytes(encriptado)
        return resultado

    # Método para descriptografar os dados usando o modo ECB

    def aes_decriptar_ecb(self, data, chave, round=10):
        resultado = b''
        for i in range(0, len(data), 16):
            bloco = list(data[i:i+16])
            decriptado = self.aes_decriptar_bloco(bloco, chave, round)
            resultado += bytes(decriptado)
        return self.unpad(resultado)

    # Método para realizar a operação XOR entre dois blocos de bytes

    def xor_bytes(self, byte1, byte2):
        bytes_resultado = []
        for x, y in zip(byte1, byte2):
            bytes_resultado.append(x ^ y)
        return bytes(bytes_resultado)

    # Método para incrementar o contador usado no modo CTR
    # O contador é incrementado em 1 a cada bloco criptografado

    def incrementa_contador(self, contador):
        contador_int = int.from_bytes(contador[-8:], 'big') + 1
        return contador[:-8] + contador_int.to_bytes(8, 'big')

    # Método para criptografar os dados usando o modo CTR

    def aes_ctr_encriptar(self, texto_claro, chave, nonce, round=10):
        assert len(chave) == 16
        assert len(nonce) == 8
        texto_cifrado = b''
        contador = nonce + b'\x00' * 8
        for i in range(0, len(texto_claro), 16):
            bloco = texto_claro[i:i+16]
            keystream_bloco = self.aes_encriptar_bloco(chave, contador, round)
            texto_cifrado_bloco = self.xor_bytes(bloco, keystream_bloco[:len(bloco)])
            texto_cifrado += texto_cifrado_bloco
            contador = self.incrementa_contador(contador)

        return texto_cifrado

    # Método para descriptografar os dados usando o modo CTR

    def aes_ctr_decriptar(self, texto_cifrado, chave, nonce, round=10):
        assert len(chave) == 16
        assert len(nonce) == 8
        texto_claro = b''
        contador = nonce + b'\x00' * 8
        for i in range(0, len(texto_cifrado), 16):
            bloco = texto_cifrado[i:i+16]
            keystream_bloco = self.aes_encriptar_bloco(chave, contador, round)
            texto_claro_bloco = self.xor_bytes(bloco, keystream_bloco[:len(bloco)])
            texto_claro += texto_claro_bloco
            contador = self.incrementa_contador(contador)

        return texto_claro


# Exemplo de uso:
input_imagem = "eu.jpg"
chave = bytes([0x2b, 0x7e, 0x15, 0x16,
             0x28, 0xae, 0xd2, 0xa6,
             0xab, 0xf7, 0x15, 0x88,
             0x09, 0xcf, 0x4f, 0x3c])

# Funções para executar o fluxo de criptografia e descriptografia usando os modos ECB e CTR

def fluxo_ecb(round):
    encriptado_imagem = "ECB_encriptado" + str(round) + ".png"
    decriptado_imagem = "ECB_decriptado" + str(round) + ".png"
    menssagem = b"Mensagem secreta AES com ECB e CTR!"
    #metadados, dados_pixel = separa_exif_e_dados_pixel(input_imagem)
    dados_rgb = np.array(recupera_rgb_de_pillow(input_imagem))
    altura, largura, canais = dados_rgb.shape
    dados_pixel = dados_rgb.tobytes()
    #if metadados and dados_pixel:
    if dados_pixel:
    # Cria uma instância da classe AES
        aes = MyAES(chave, os.urandom(8), os.urandom(16))
        print(f"Nonce:{aes.nonce.hex()}\nIV:{aes.iv.hex()}\nChave:{aes.chave.hex()}\nChave-len:{len(aes.chave)}")

    # Encripta os dados da imagem
        encriptado_data = aes.aes_encriptar_ecb(dados_pixel, chave, round=round)
        encriptado_menssagem = aes.aes_encriptar_ecb(menssagem, chave, round=round)
        print(f"Mensagem Encriptada: {encriptado_menssagem.hex()} round {round}")

    # Salva a imagem encriptada
        #salva_imagem_com_exif(encriptado_imagem, metadados, encriptado_data)
        encriptado_paded = encriptado_data[:altura * largura * canais]
        encriptado_pixels = np.frombuffer(encriptado_paded, dtype=np.uint8).reshape((altura, largura, canais))
        converte_array_para_imagem(encriptado_pixels, encriptado_imagem)
        print(f"O hash da imagem encriptada ECB no round {round} é: {gera_hash_arquivo(encriptado_imagem)}")

    # Decripta os dados da imagem
        decriptado_data = aes.aes_decriptar_ecb(encriptado_data, chave, round=round)
        decriptado_menssagem = aes.aes_decriptar_ecb(encriptado_menssagem, chave, round=round)
        print(f"Mensagem Decriptada: {decriptado_menssagem.decode()} round {round}")

    # Salva a imagem decriptada
        #salva_imagem_com_exif(decriptado_imagem, metadados, decriptado_data)
        decriptado_paded = decriptado_data[:altura * largura * canais]
        decriptado_pixels = np.frombuffer(decriptado_paded, dtype=np.uint8).reshape((altura, largura, canais))
        converte_array_para_imagem(decriptado_pixels, decriptado_imagem)
        print(f"O hash da imagem decriptada ECB no round {round} é: {gera_hash_arquivo(decriptado_imagem)}")

    print(f"Chave de encriptação (guarde isso em segredo!): {chave.hex()}")

    try:
        img = Image.open(decriptado_imagem)  # Substitua "sua_imagem.jpg" pelo caminho do seu arquivo
    except FileNotFoundError:
        print("Erro: Arquivo não encontrado.")
    except Exception as e:
        print(f"Erro ao abrir a imagem: {e}")
    else:
        # Exiba a imagem usando matplotlib
        plt.imshow(img)
        plt.axis('off')  # Desativa os eixos
        plt.show()

    try:
        img = Image.open(encriptado_imagem)
    except FileNotFoundError:
        print("Erro: Arquivo não encontrado.")
    except Exception as e:
        print(f"Erro ao abrir a imagem: {e}")
    else:
        # Exiba a imagem usando matplotlib
        plt.imshow(img)
        plt.axis('off')  # Desativa os eixos
        plt.show()

def fluxo_ctr(round):
    encriptado_imagem = "CTR_encriptado" + str(round) + ".png"
    decriptado_imagem = "CTR_decriptado" + str(round) + ".png"
    menssagem = b"Mensagem secreta AES com ECB e CTR!"
    #metadados, dados_pixel = separa_exif_e_dados_pixel(input_imagem)
    dados_rgb = np.array(recupera_rgb_de_pillow(input_imagem))
    altura, largura, canais = dados_rgb.shape
    dados_pixel = dados_rgb.tobytes()
    #if metadados and dados_pixel:
    if dados_pixel:
    # Cria uma instância da classe AES
        aes = MyAES(chave, os.urandom(8), os.urandom(16))
        print(f"Nonce:{aes.nonce.hex()}\nIV:{aes.iv.hex()}\nChave:{aes.chave.hex()}\nChave-len:{len(aes.chave)}")

    # Encripta os dados da imagem
        encriptado_data = aes.aes_ctr_encriptar(dados_pixel, chave, aes.nonce, round=round)
        encriptado_menssagem = aes.aes_ctr_encriptar(menssagem, chave, aes.nonce, round=round)
        print(f"Mensagem Encriptada: {encriptado_menssagem.hex()} round {round}")

    # Salva a imagem encriptada
        #salva_imagem_com_exif(encriptado_imagem, metadados, encriptado_data)
        encriptado_paded = encriptado_data[:altura * largura * canais]
        encriptado_pixels = np.frombuffer(encriptado_paded, dtype=np.uint8).reshape((altura, largura, canais))
        converte_array_para_imagem(encriptado_pixels, encriptado_imagem)
        print(f"O hash da imagem encriptada CTR no round {round} é: {gera_hash_arquivo(encriptado_imagem)}")

    # Decripta os dados da imagem
        decriptado_data = aes.aes_ctr_decriptar(encriptado_data, chave, aes.nonce, round=round)
        decriptado_menssagem = aes.aes_ctr_decriptar(encriptado_menssagem, chave, aes.nonce, round=round)
        print(f"Mensagem Decriptada: {decriptado_menssagem.decode()} round {round}")

    # Salva a imagem decriptada
        #salva_imagem_com_exif(decriptado_imagem, metadados, decriptado_data)
        decriptado_paded = decriptado_data[:altura * largura * canais]
        decriptado_pixels = np.frombuffer(decriptado_paded, dtype=np.uint8).reshape((altura, largura, canais))
        converte_array_para_imagem(decriptado_pixels, decriptado_imagem)
        print(f"O hash da imagem encriptada CTR no round {round} é: {gera_hash_arquivo(decriptado_imagem)}")

    print(f"Chave de encriptação (guarde isso em segredo!): {chave.hex()}")

    try:
        img = Image.open(decriptado_imagem)
    except FileNotFoundError:
        print("Erro: Arquivo não encontrado.")
    except Exception as e:
        print(f"Erro ao abrir a imagem: {e}")
    else:
        plt.imshow(img)
        plt.axis('off')  
        plt.show()

    try:
        img = Image.open(encriptado_imagem)  
    except FileNotFoundError:
        print("Erro: Arquivo não encontrado.")
    except Exception as e:
        print(f"Erro ao abrir a imagem: {e}")
    else:
        # Exiba a imagem usando matplotlib
        plt.imshow(img)
        plt.axis('off') 
        plt.show()

def main():
    input_imagem = "eu.jpg"
    print(f"O hash da imagem original é: {gera_hash_arquivo(input_imagem)}")
    chave = bytes([0x2b, 0x7e, 0x15, 0x16,
             0x28, 0xae, 0xd2, 0xa6,
             0xab, 0xf7, 0x15, 0x88,
             0x09, 0xcf, 0x4f, 0x3c])
    print("Execução ECB")
    fluxo_ecb(1)
    fluxo_ecb(5)
    fluxo_ecb(9)
    fluxo_ecb(13)

    print("Execução CTR")
    fluxo_ctr(1)
    fluxo_ctr(5)
    fluxo_ctr(9)
    fluxo_ctr(13)

