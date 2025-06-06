import aes
import math
import hashlib
import os
import base64
from sympy import randprime

# Função que faz a conversão de uma entrada de texto (string ou bytes) para um inteiro.
def texto_para_inteiro(texto):
    # Se 'texto' for uma string, .encode('utf-8') fará a conversão.
    # Se 'texto' já for bytes int.from_bytes(texto, 'big') fará a conversão.
    if isinstance(texto, str):
        return int.from_bytes(texto.encode('utf-8'), 'big')
    elif isinstance(texto, bytes):
        return int.from_bytes(texto, 'big')
    else:
        raise TypeError("Entrada para texto_para_inteiro deve ser str ou bytes.")


# Função que converte um inteiro de volta para texto (string ou bytes).
def inteiro_para_texto(inteiro):
    comprimento = (inteiro.bit_length() + 7) // 8
    return inteiro.to_bytes(comprimento, 'big').decode('utf-8', errors='ignore')

# Função que gera números primos aleatórios de tamanho especificado em bits.
def gerar_primos(bits=1024):
    inicio = 2 ** (bits - 1)
    fim = 2 ** bits - 1
    return randprime(inicio, fim)

# Classe RSA que implementa o algoritmo RSA com funcionalidades de encriptação,
# decriptação e geração de chaves.
class RSA:
    def __init__(self, p, q):
        self.p = p
        self.q = q
        self.n = p * q
        self.phi = (p - 1) * (q - 1)
        self.e = 65537

    # Método para calcular a potência modular  
    def power(self, base, expoente, modulo):
        return pow(base, expoente, modulo)

    # Método para calcular o máximo divisor comum usando o algoritmo de Euclides estendido
    def euclides_estendido(self, val1, val2):
        if val2 == 0:
            return (val1, 1, 0)
        else:
            maximo_divisor_comum, cof_x1, cof_y1 = self.euclides_estendido(val2, val1 % val2)
            cof_x = cof_y1
            cof_y = cof_x1 - (val1 // val2) * cof_y1
            return (maximo_divisor_comum, cof_x, cof_y)

    # Método para calcular o inverso modular usando o algoritmo de Euclides estendido
    def inverso_modular(self, e, phi):
        maior_divisor_comum, x, y = self.euclides_estendido(e, phi)
        if maior_divisor_comum != 1:
            raise Exception("Inverso modular não existe")
        else:
            return x % phi

    # Método para gerar as chaves RSA
    def gera_chaves(self):
        if math.gcd(self.e, self.phi) != 1:
            raise Exception("e não é coprimo com phi")
        self.d = self.inverso_modular(self.e, self.phi)
        return (self.e, self.d, self.n)

    # Método para encriptar uma mensagem usando a chave pública (e, n)
    # ou a chave privada (d, n) dependendo do parâmetro usar_chave_privada.
    def encripta(self, mensagem, usar_chave_privada=False):
        # A mensagem aqui deve ser um inteiro, já convertido por texto_para_inteiro
        if isinstance(mensagem, (str, bytes)): 
            raise TypeError("Mensagem para encripta deve ser um inteiro.")
        chave = self.d if usar_chave_privada else self.e
        return self.power(mensagem, chave, self.n)

    # Método para decriptar uma mensagem usando a chave privada (d, n)
    # ou a chave pública (e, n) dependendo do parâmetro usar_chave_privada.
    def decripta(self, mensagem_encriptada, usar_chave_privada=True):
        chave = self.d if usar_chave_privada else self.e
        return self.power(mensagem_encriptada, chave, self.n)

    # Método para decriptar e converter a resposta direto para texto.
    def decripta_texto(self, mensagem_encriptada, usar_chave_privada=True):
        inteiro = self.decripta(mensagem_encriptada, usar_chave_privada=usar_chave_privada)
        return inteiro_para_texto(inteiro)


# Classe OaepRSA que estende a classe RSA para implementar o esquema de padding OAEP.
# Inserindo aleatoriedade na geração de máscaras e blocos de dados.
class OaepRSA(RSA):

    # Método para gerar uma máscara de tamanho especificado a partir de uma semente.
    # A máscara é gerada usando uma função hash (por padrão, SHA-256).
    def gerar_mascara(self, semente, tamanho, hash_func=hashlib.sha256):
        mascara = bytearray()
        contador = 0
        while len(mascara) < tamanho:
            contador_bytes = contador.to_bytes(4, 'big')
            entrada = semente + contador_bytes
            mascara += hash_func(entrada).digest()
            contador += 1
        return bytes(mascara[:tamanho])

    # Método que gera os blocos de dados para o esquema OAEP.
    def gerar_bloco_dados(self, mensagem, tamanho_mod_rsa, hash_func=hashlib.sha256):
        # Garante que mensagem_bytes seja bytes
        mensagem_bytes = mensagem if isinstance(mensagem, bytes) else mensagem.encode('utf-8')
        tamanho_menssagem = len(mensagem_bytes)
        label = b""
        tamanho_hash = hash_func().digest_size
        comprimento_hash = hash_func(label).digest()

        if tamanho_menssagem > tamanho_mod_rsa - 2 * tamanho_hash - 2:
            raise ValueError("Mensagem muito longa para o tamanho do bloco RSA")

        padding = b'\x00' * (tamanho_mod_rsa - tamanho_menssagem - 2 * tamanho_hash - 2)
        dados = comprimento_hash + padding + b'\x01' + mensagem_bytes
        return dados

    # Método que aplica a máscara gerada sobre os dados usando a semente.
    def aplicar_mascara(self, dados, semente, tamanho, hash_func=hashlib.sha256):
        mascara = self.gerar_mascara(semente, tamanho, hash_func)
        return bytes(d ^ m for d, m in zip(dados, mascara))

    # Método que codifica a mensagem usando o esquema OAEP.
    def oaep_codifica(self, mensagem, tamanho_mod_rsa, hash_func=hashlib.sha256):
        tamanho_hash = hash_func().digest_size
        dado = self.gerar_bloco_dados(mensagem, tamanho_mod_rsa, hash_func)
        semente = os.urandom(tamanho_hash)

        dados_mascarados = self.aplicar_mascara(dado, semente, tamanho_mod_rsa - tamanho_hash - 1, hash_func)
        semente_mascarada = self.aplicar_mascara(semente, dados_mascarados, tamanho_hash, hash_func)

        oaep_codificado = b'\x00' + semente_mascarada + dados_mascarados
        return oaep_codificado

    # Método que extrai a semente e os dados mascarados do OAEP codificado.
    def extrair_semente_dados(self, oaep_codificado, tamanho_hash):
        Y = oaep_codificado[0]
        semente_mascarada = oaep_codificado[1:tamanho_hash+1]
        dados_mascarados = oaep_codificado[tamanho_hash+1:]
        return Y, semente_mascarada, dados_mascarados

    # Método que remove o padding OAEP dos dados decodificados.
    def unpad(self, dados, tamanho_hash, hash_func=hashlib.sha256):
        comprimento_hash = hash_func(b"").digest()
        if dados[:tamanho_hash] != comprimento_hash:
            raise ValueError("Hash incorreto no formato OAEP")
        idx = dados.find(b'\x01', tamanho_hash)
        if idx == -1:
            raise ValueError("Delimitador não encontrado")
        return dados[idx+1:]

    # Método que decodifica a mensagem usando o esquema OAEP.
    def oaep_decodifica(self, oaep_codificado, tamanho_mod_rsa, hash_func=hashlib.sha256):
        tamanho_hash = hash_func().digest_size
        Y, semente_mascarada, dados_mascarados = self.extrair_semente_dados(oaep_codificado, tamanho_hash)

        semente = self.aplicar_mascara(semente_mascarada, dados_mascarados, tamanho_hash, hash_func)
        dados = self.aplicar_mascara(dados_mascarados, semente, tamanho_mod_rsa - tamanho_hash - 1, hash_func)

        mensagem = self.unpad(dados, tamanho_hash, hash_func)
        return mensagem.decode('utf-8', errors='ignore') # Adicionado errors='ignore' para caracteres inválidos

    # Método que encripta mensagens usando OAEP com RSA.
    def rsa_oaep_encripta(self, mensagem, usar_chave_privada=False):
        tamanho_mod_rsa = (self.n.bit_length() + 7) // 8
        oaep_codificado = self.oaep_codifica(mensagem, tamanho_mod_rsa)
        oaep_codificado_int = int.from_bytes(oaep_codificado, 'big')
        cifra = self.encripta(oaep_codificado_int, usar_chave_privada=usar_chave_privada)
        return cifra

    # Método que decripta mensagens usando OAEP com RSA.
    def rsa_oaep_decripta(self, cifra, usar_chave_privada=True):
        tamanho_mod_rsa = (self.n.bit_length() + 7) // 8
        mensagem_int = self.decripta(cifra, usar_chave_privada=usar_chave_privada)
        oaep_codificado = mensagem_int.to_bytes(tamanho_mod_rsa, 'big')
        mensagem = self.oaep_decodifica(oaep_codificado, tamanho_mod_rsa)
        return mensagem


# Classe CifracaoHibrida que combina RSA com OAEP e AES para cifragem híbrida.
class CifracaoHibrida(OaepRSA):
    
    # Método que cifra uma mensagem usando AES e RSA com OAEP.
    def cifra_hibrida(self, dados_input, usar_chave_privada=False):
        # dados_input pode ser bytes (de arquivo) ou str (de mensagem digitada)
        if isinstance(dados_input, str):
            dados_input = dados_input.encode('utf-8')
        
        chave_aes = os.urandom(16) # Chave AES de 128 bits
        aes_cifra = aes.MyAES(chave_aes, os.urandom(8), os.urandom(16))
        mensagem_cifrada = aes_cifra.aes_encriptar_ecb(dados_input, chave_aes)

        chave_aes_cifrada = self.rsa_oaep_encripta(chave_aes.hex(), usar_chave_privada=usar_chave_privada)
        return chave_aes_cifrada, mensagem_cifrada

    # Método que decifra uma mensagem cifrada usando AES e RSA com OAEP.
    def decifra_hibrida(self, chave_aes_cifrada, mensagem_cifrada, usar_chave_privada=True):
        chave_aes_hex = self.rsa_oaep_decripta(chave_aes_cifrada, usar_chave_privada=usar_chave_privada)
        chave_aes = bytes.fromhex(chave_aes_hex)
        aes_cifra = aes.MyAES(chave_aes, os.urandom(8), os.urandom(16))
        mensagem_decifrada = aes_cifra.aes_decriptar_ecb(mensagem_cifrada, chave_aes)
        return mensagem_decifrada

# Classe Assinador que estende CifracaoHibrida para adicionar funcionalidades de assinatura
# e verificação digital.

class Assinador(CifracaoHibrida):
    
    # Construtor que recebe um objeto RSA para usar nas assinaturas.
    def __init__(self, rsa_obj):
        self.rsa_obj = rsa_obj

    # Método que assina os dados de entrada usando o RSA.
    def assinar(self, dados_input, rsa_obj=None):
        if rsa_obj is None:
            rsa_obj = self.rsa_obj
        
        # Garante que dados_input seja bytes para o hashing
        if isinstance(dados_input, str):
            dados_input = dados_input.encode('utf-8')

        hash_mensagem = hashlib.sha3_256(dados_input).digest()
        hash_int = int.from_bytes(hash_mensagem, 'big')
        assinatura = rsa_obj.encripta(hash_int, usar_chave_privada=True)
        assinatura_b64 = base64.b64encode(assinatura.to_bytes((assinatura.bit_length() + 7) // 8, 'big')).decode()
        return assinatura_b64
    
    # Método que assina um arquivo, lendo seu conteúdo e passando para o método assinar.
    def assinar_arquivo(self, caminho_arquivo, rsa_obj=None):
        if rsa_obj is None:
            rsa_obj = self.rsa_obj
        try:
            with open(caminho_arquivo, 'rb') as arquivo:
                conteudo = arquivo.read()
                return self.assinar(conteudo, rsa_obj) # Passa bytes diretamente
        except FileNotFoundError:
            print(f"Erro: Arquivo '{caminho_arquivo}' não encontrado.")
            return None
        except Exception as e:
            print(f"Erro ao assinar o arquivo: {e}")
            return None

    # Método que verifica a assinatura de dados de entrada.
    def verificar(self, dados_input, assinatura_b64, rsa_obj=None):
        if rsa_obj is None:
            rsa_obj = self.rsa_obj
        
        # Garante que dados_input seja bytes para o hashing
        if isinstance(dados_input, str):
            dados_input = dados_input.encode('utf-8')

        assinatura_bytes = base64.b64decode(assinatura_b64.encode())
        assinatura_int = int.from_bytes(assinatura_bytes, 'big')
        hash_recuperado_int = rsa_obj.decripta(assinatura_int, usar_chave_privada=False)
        hash_recuperado = hash_recuperado_int.to_bytes((hash_recuperado_int.bit_length() + 7) // 8, 'big')
        hash_original = hashlib.sha3_256(dados_input).digest()
        return hash_original == hash_recuperado
    
    # Método que verifica a assinatura de um arquivo, lendo seu conteúdo e passando para o método verificar.
    def verificar_arquivo(self, caminho_arquivo, assinatura_b64, rsa_obj=None):
        if rsa_obj is None:
            rsa_obj = self.rsa_obj
        try:
            with open(caminho_arquivo, 'rb') as arquivo:
                conteudo = arquivo.read()
                return self.verificar(conteudo, assinatura_b64, rsa_obj) # Passa bytes diretamente
        except FileNotFoundError:
            print(f"Erro: Arquivo '{caminho_arquivo}' não encontrado.")
            return False
        except Exception as e:
            print(f"Erro ao verificar o arquivo: {e}")
            return False

# Funções auxiliares para obter dados de entrada e salvar dados de saída

# Função para obter dados de entrada do usuário, seja uma mensagem digitada ou um arquivo.
def obter_dados_entrada():
    """Função para obter entrada do usuário (mensagem ou arquivo)."""
    while True:
        escolha_origem = input("Deseja usar uma (m)ensagem ou um (a)rquivo? ").lower()
        if escolha_origem == 'm':
            return input("Digite a mensagem: ").encode('utf-8') # Sempre retorna bytes
        elif escolha_origem == 'a':
            caminho_arquivo = input("Digite o caminho do arquivo: ")
            try:
                with open(caminho_arquivo, 'rb') as f:
                    return f.read() # Retorna bytes diretamente do arquivo
            except FileNotFoundError:
                print("Arquivo não encontrado. Tente novamente.")
            except Exception as e:
                print(f"Erro ao ler o arquivo: {e}. Tente novamente.")
        else:
            print("Escolha inválida. Digite 'm' para mensagem ou 'a' para arquivo.")

# Método para salvar os dados de saída, seja uma mensagem cifrada, decifrada ou assinatura.
def salvar_dados_saida(dados, tipo_operacao, is_file_input=False, original_filepath=None):
    if is_file_input and original_filepath:
        nome_base, extensao = os.path.splitext(original_filepath)
        nome_saida = f"{nome_base}_{tipo_operacao}{extensao}"
    else:
        nome_saida = f"saida_{tipo_operacao}.bin" # Padrão para mensagens ou se não houver arquivo original

    try:
        with open(nome_saida, 'wb') as f:
            f.write(dados)
        print(f"Dados {tipo_operacao} salvos em '{nome_saida}'")
    except Exception as e:
        print(f"Erro ao salvar os dados {tipo_operacao}: {e}")

# Função principal que executa o programa, gerando chaves RSA, assinando e verificando mensagens.
if __name__ == "__main__":
    # Gerar dois primos grandes para RSA
    p = gerar_primos(1024)
    q = gerar_primos(1024)

    # Inicializar a cifra híbrida com os primos gerados
    # E criar o objeto Assinador com a cifra híbrida
    rsa_hibrida = CifracaoHibrida(p, q)
    rsa_hibrida.gera_chaves()
    assinador_obj = Assinador(rsa_hibrida) # Renomeado para evitar conflito com a função 'assinar'

    print("Gerando chaves RSA (isso pode levar um tempo para chaves grandes)...")
    e_chave, d_chave, n_chave = rsa_hibrida.gera_chaves()
    print("Chaves RSA geradas com sucesso!")
    print(f"Chave Pública (e, n): ({e_chave}, {n_chave})")
    print(f"Chave Privada (d, n): ({d_chave}, {n_chave})")

    # Menu principal para interagir com o usuário
    while True:
        print("\n--- Menu Principal ---")
        print("1. Assinar")
        print("2. Verificar Assinatura")
        print("3. Criptografar (Cifra Híbrida)")
        print("4. Descriptografar (Cifra Híbrida)")
        print("5. Sair")

        escolha = input("Escolha uma opção: ")

        if escolha == '1':
            dados_para_assinar = obter_dados_entrada()
            if dados_para_assinar is None:
                continue

            # Determinar se a entrada original era um arquivo para nomear o arquivo de saída
            is_file_input = False
            original_filepath = None
            if isinstance(dados_para_assinar, bytes): # Se veio de um arquivo ou mensagem, já é bytes
                if b'\n' not in dados_para_assinar and len(dados_para_assinar) > 100: # Heurística simples para detectar arquivo
                    # Se foi um arquivo, precisamos do caminho para nomear o arquivo de saída
                    # Isso é um pouco complicado aqui, idealmente a função obter_dados_entrada deveria retornar mais info.
                    # Por simplicidade, vamos apenas verificar se a entrada era grande.
                    pass # Não podemos saber o nome do arquivo original aqui facilmente

            assinatura = assinador_obj.assinar(dados_para_assinar)
            if assinatura:
                print(f"Assinatura (Base64): {assinatura}")
                salvar = input("Deseja salvar a assinatura em um arquivo? (s/n): ").lower()
                if salvar == 's':
                    nome_arquivo_assinatura = input("Digite o nome do arquivo para salvar a assinatura (ex: assinatura.txt): ")
                    try:
                        with open(nome_arquivo_assinatura, 'w') as f:
                            f.write(assinatura)
                        print(f"Assinatura salva em '{nome_arquivo_assinatura}'")
                    except Exception as e:
                        print(f"Erro ao salvar a assinatura: {e}")

        elif escolha == '2':
            dados_originais = obter_dados_entrada()
            if dados_originais is None:
                continue
            
            assinatura_input_origem = input("A assinatura está em um (f)ile ou será (d)igitada? ").lower()
            assinatura_b64 = None
            if assinatura_input_origem == 'd':
                assinatura_b64 = input("Digite a assinatura (Base64): ")
            elif assinatura_input_origem == 'f':
                caminho_assinatura = input("Digite o caminho do arquivo da assinatura: ")
                try:
                    with open(caminho_assinatura, 'r') as f:
                        assinatura_b64 = f.read().strip()
                except FileNotFoundError:
                    print(f"Erro: Arquivo de assinatura '{caminho_assinatura}' não encontrado.")
                    continue
                except Exception as e:
                    print(f"Erro ao ler arquivo de assinatura: {e}")
                    continue
            else:
                print("Escolha inválida.")
                continue

            if assinatura_b64:
                valido = assinador_obj.verificar(dados_originais, assinatura_b64)
                print(f"Assinatura válida? {'Sim' if valido else 'Não'}")

        elif escolha == '3':
            dados_para_criptografar = obter_dados_entrada()
            if dados_para_criptografar is None:
                continue

            chave_aes_cifrada, mensagem_cifrada = rsa_hibrida.cifra_hibrida(dados_para_criptografar, usar_chave_privada=False)
            print(f"Chave AES Cifrada (inteiro): {chave_aes_cifrada}")
            print(f"Mensagem Cifrada (hex): {mensagem_cifrada.hex()}")
            
            # Salvar chave AES cifrada e mensagem cifrada
            salvar_dados_saida(str(chave_aes_cifrada).encode('utf-8'), "chave_aes_cifrada")
            salvar_dados_saida(mensagem_cifrada, "mensagem_cifrada")


        elif escolha == '4':
            try:
                chave_aes_cifrada_str = input("Digite a chave AES cifrada (inteiro): ")
                chave_aes_cifrada = int(chave_aes_cifrada_str)
                
                mensagem_cifrada_hex = input("Digite a mensagem cifrada (hex): ")
                mensagem_cifrada = bytes.fromhex(mensagem_cifrada_hex)

                mensagem_decifrada_bytes = rsa_hibrida.decifra_hibrida(chave_aes_cifrada, mensagem_cifrada, usar_chave_privada=True)
                
                try:
                    mensagem_decifrada_str = mensagem_decifrada_bytes.decode('utf-8')
                    print(f"Mensagem Decifrada: {mensagem_decifrada_str}")
                except UnicodeDecodeError:
                    print("Mensagem Decifrada (bytes, não pôde ser decodificada como UTF-8):")
                    print(mensagem_decifrada_bytes)
                
                # Perguntar ao usuário se deseja salvar a mensagem decifrada
                salvar = input("Deseja salvar a mensagem decifrada em um arquivo? (s/n): ").lower()
                if salvar == 's':
                    nome_arquivo_decifrado = input("Digite o nome do arquivo para salvar a mensagem decifrada (ex: decifrado.txt ou decifrado.bin): ")
                    try:
                        with open(nome_arquivo_decifrado, 'wb') as f:
                            f.write(mensagem_decifrada_bytes)
                        print(f"Mensagem decifrada salva em '{nome_arquivo_decifrado}'")
                    except Exception as e:
                        print(f"Erro ao salvar a mensagem decifrada: {e}")

            except ValueError:
                print("Entrada inválida. Certifique-se de que a chave é um número e a mensagem é um hex válido.")
            except Exception as e:
                print(f"Erro ao descriptografar: {e}")

        elif escolha == '5':
            print("Saindo...")
            break
        else:
            print("Opção inválida. Por favor, escolha uma opção de 1 a 5.")