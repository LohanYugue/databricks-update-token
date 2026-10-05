import subprocess
import json
import sys
import datetime
import os
import re
import boto3
import requests
from dotenv import load_dotenv


def run_command(command):
    """
    Executa um comando no shell e retorna a saída.
    Lança uma exceção em caso de erro.
    """
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Erro ao executar comando:\n{command}\n{result.stderr}")
    return result.stdout

def update_databricks_secret(scope, secret_name, secret_value, workspace):
    """
    Atualiza uma secret no Databricks via CLI.
    Suporta strings simples (tokens) ou strings JSON formatadas.
    """
    print(f"🔐 Atualizando secret '{secret_name}' no scope '{scope}' do Databricks workspace {workspace} ...")
    
    # Escapa aspas duplas internas para evitar quebra de sintaxe no prompt do Windows CMD/shell
    escaped_value = secret_value.replace('"', '\\"')
    command = fr'C:\databricks\databricks.exe secrets put-secret {scope} {secret_name} --string-value "{escaped_value}" -p {workspace}'

    run_command(command)
    print("✅ Secret atualizada no Databricks com sucesso.")

def update_aws_secret(secret_id, secret_dict):
    """
    Atualiza a secret no AWS Secrets Manager com o dicionário atualizado.
    """
    print("📦 Atualizando secret no AWS Secrets Manager...")
    client = boto3.client("secretsmanager", region_name='us-east-1')
    client.update_secret(
        SecretId=secret_id,
        SecretString=json.dumps(secret_dict)
    )
    print(f"✅ Secret '{secret_id}' atualizada com sucesso na AWS.")

def process_secret(secret_id, lifetime_seconds=7889400):
    """
    Processo principal de renovação da credencial.
    """
    client = boto3.client("secretsmanager")

    # 1. Busca secret existente
    print(f"🔎 Buscando secret no AWS Secrets Manager: {secret_id}")

    try:
        secret_value = client.get_secret_value(SecretId=secret_id)
    except Exception as e:
        if 'ExpiredTokenException' in str(e) or 'token included in the request is invalid.' in str(e):
            raise Exception("Aparentemente você não passou no arquivo '.env' os comandos SET AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY e AWS_SESSION_TOKEN válidos... Lembrando que são credenciais temporárias e cada vez que for executar, é necessário atualizar no '.env'")
        else:
            raise Exception(f"Erro inesperado ao executar comando, detalhes :{e}")

    secret_dict = json.loads(secret_value["SecretString"])

    # Salva valores antigos (se existirem)
    old_token = secret_dict.get("token")
    old_expiration = secret_dict.get("expiration_time")

    # --- ATRIBUTO DE CONFIGURAÇÃO NO JSON DA SECRET ---
    # Se 'store_full_response' for true, envia o JSON completo para o Databricks
    store_full_response = str(secret_dict.get("store_full_response", False)).lower() in ("true", "1")

    # --- VALIDAÇÃO DA EXPIRAÇÃO DE TOKEN ---
    if old_token and old_expiration:
        try:
            expiration_date_obj = datetime.datetime.strptime(old_expiration, "%Y-%m-%d").date()
            today = datetime.datetime.now(datetime.UTC).date()
            days_remaining = (expiration_date_obj - today).days

            if days_remaining > 15:
                print(f"✅ O token ainda é válido por {days_remaining} dias (expira em {old_expiration}). A atualização não é necessária.")
                return 
            elif days_remaining <= 0:
                 print(f"🚨 O token expirou há {-days_remaining} dias (em {old_expiration}). Iniciando renovação urgente...")
            else:
                print(f"⚠️ O token expira em {days_remaining} dias (em {old_expiration}). Iniciando renovação...")
        except ValueError:
            print(f"⚠️️ Não foi possível analisar a data de expiração antiga ('{old_expiration}'). Prosseguindo com a renovação.")
    else:
        print("ℹ️ Token ou data de expiração antigos não encontrados. Prosseguindo com a geração de um novo token.")

    # 2. Extrai campos da Secret
    application_id = secret_dict["application_id"]
    workspace = secret_dict["workspace"]

    # Campos opcionais
    scope = secret_dict.get("scope")
    secret_name = secret_dict.get("secret")
    workspace_scope = secret_dict.get("workspace_scope")
    email_address = secret_dict.get("email")
    
    # Campos para lógica OAuth
    auth_method = secret_dict.get("sp_auth_method", "basic")
    account_id = secret_dict.get("account_id", "")

    lifetime_seconds = int(lifetime_seconds) if lifetime_seconds else 7889400

    response_data = {}

    # 3. Fluxo Condicional de Geração de Token/Secret
    if auth_method == "oauth_m2m":
        print("\n🚀 Iniciando fluxo de renovação OAuth M2M (Account API)...")

        if not account_id or not str(account_id).strip():
            raise ValueError("O campo 'account_id' é obrigatório e deve ser especificado para a autenticação OAuth M2M.")

        load_dotenv(override=True)

        env_client_id = os.environ.get("CLIENT_ID")
        env_client_secret = os.environ.get("CLIENT_SECRET")

        if not env_client_id or not env_client_secret:
            raise Exception("ERRO: As variáveis de ambiente CLIENT_ID e CLIENT_SECRET não foram encontradas. Elas são obrigatórias para gerar o token Account-Level.")

        # Passo 1 - Gerar token account-level usando as variáveis de ambiente
        print("   ↳ 1. Gerando token account-level...")
        token_url = f"https://accounts.cloud.databricks.com/oidc/accounts/{account_id}/v1/token"
        
        token_resp = requests.post(
            token_url,
            auth=(env_client_id, env_client_secret),
            data={"grant_type": "client_credentials", "scope": "all-apis"}
        )
        token_resp.raise_for_status()
        oauth_token = token_resp.json()["access_token"]

        # Passo 2 - Obter o internal_id (Resource ID) do Service Principal a ser renovado
        print("   ↳ 2. Obtendo o Service Principal ID interno via SCIM...")
        scim_url = f"https://accounts.cloud.databricks.com/api/2.0/accounts/{account_id}/scim/v2/ServicePrincipals"
        scim_resp = requests.get(
            scim_url,
            headers={"Authorization": f"Bearer {oauth_token}"},
            params={"filter": f"applicationId eq '{application_id}'"}
        )
        scim_resp.raise_for_status()
        
        resources = scim_resp.json().get("Resources", [])
        if not resources:
            raise Exception(f"Service Principal com applicationId {application_id} não encontrado na conta {account_id}.")
        internal_id = resources[0]["id"]

        # Passo 3 - Gerar a nova secret para este Service Principal
        print(f"   ↳ 3. Gerando nova Client Secret para o ID interno: {internal_id}...")
        secrets_url = f"https://accounts.cloud.databricks.com/api/2.0/accounts/{account_id}/servicePrincipals/{internal_id}/credentials/secrets"
        secrets_resp = requests.post(
            secrets_url,
            headers={"Authorization": f"Bearer {oauth_token}"},
            json={"lifetime": f"{lifetime_seconds}s"}
        )
        secrets_resp.raise_for_status()

        # Guarda a resposta JSON completa
        response_data = secrets_resp.json()
        token_value = response_data["secret"]

        # Calcula a nova data de expiração
        expiry_datetime = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=lifetime_seconds)
        expiration_date = expiry_datetime.strftime("%Y-%m-%d")

    else:
        # Fluxo OBO Token (Basic)
        print("\n🔧 Gerando novo token OBO com Databricks CLI...")
        command = fr"C:\databricks\databricks.exe token-management create-obo-token {application_id} --lifetime-seconds {lifetime_seconds} -p {workspace}"
        output = run_command(command)
        response_data = json.loads(output)

        token_value = response_data["token_value"]
        expiry_time_ms = response_data["token_info"]["expiry_time"]
        expiration_date = datetime.datetime.fromtimestamp(expiry_time_ms / 1000, tz=datetime.UTC).strftime("%Y-%m-%d")

    # 4. Atualiza APENAS o valor do token simples na secret da AWS
    update_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
    secret_dict["token"] = token_value
    secret_dict["expiration_time"] = expiration_date
    secret_dict["update_time"] = update_time

    # 5. Atualiza secret na AWS (apenas com o token simples)
    update_aws_secret(secret_id, secret_dict)

    # 6. Atualiza secret no Databricks
    if scope and secret_name:
        # Se store_full_response for True, envia o JSON completo da resposta; caso contrário, envia apenas o token
        if store_full_response and response_data:
            databricks_payload = json.dumps(response_data)
            print("📦 Inserindo a resposta inteira da API no Secret Scope do Databricks...")
        else:
            databricks_payload = token_value
            print("🔑 Inserindo apenas o valor do token no Secret Scope do Databricks...")

        update_databricks_secret(scope, secret_name, databricks_payload, workspace_scope or workspace)
    else:
        print("ℹ️ Campos 'scope' e/ou 'secret' não encontrados. O Secret Scope do Databricks não será atualizado.")

    # 7. Resumo
    print(f"\n📋 Resumo da atualização:")
    print(f"🔒 Método utilizado: {auth_method}")
    if old_token:
        print(f"🔑 Token/Secret antigo: {old_token[:5]}... (ocultado)")
    if old_expiration:
        print(f"📅 Expiração antiga: {old_expiration}")

    print(f"\n🔑 Novo Token/Secret na AWS: {token_value[:5]}... (ocultado)")
    print(f"📅 Expira em: {expiration_date}")
    print(f"🕒 Atualizado em: {update_time}")
    print(f"✉️ Email: {email_address or 'N.A'}")

    # 8. Texto adicional
    email_list = [e.strip() for e in re.split(r"[,;\s]+", email_address or "") if e.strip()]
    if email_list:
        sql_warehouse_name = secret_id.split("/")[-1]
        single_email_warning = (
            "\nPoderia informar um ou mais nomes (email) para receber esse novo token para evitar que tenha interrupção dos serviços por falta de comunicação a todos os envolvidos ?\n"
            if len(email_list) == 1
            else ""
        )

        print(f"""
[ IMPORTANTE ] Atualização de Credenciais SQL Warehouse Databricks - {sql_warehouse_name}
Prezado(a),

Este email contém suas novas credenciais de acesso para o SQL Warehouse {sql_warehouse_name}

Sua credencial antiga, associada ao Application ID {application_id} e com vencimento em {old_expiration}, foi substituída.

Application ID: {application_id}
Nova Credencial: {token_value}
Validade: {expiration_date}

Por favor, atualize suas configurações para usar a nova credencial antes da data de expiração da antiga para evitar interrupções.
{single_email_warning}
Em caso de dúvidas, estamos à disposição.

Atenciosamente,
""")

def main():
    env_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(env_file_path):
        with open(env_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not str(line).strip().startswith('#'):
                    subprocess.run(line, shell=True)
                    if line.lower().startswith("set "):
                        key_value = line[4:].strip()
                        if "=" in key_value:
                            key, value = key_value.split("=", 1)
                            os.environ[key.strip()] = value.strip()

    if len(sys.argv) not in (2, 3):
        print("Uso: python update_databricks_secret.py <nome_da_secret> [lifetime_seconds]")
        sys.exit(1)

    env_client_id = os.environ.get("CLIENT_ID")
    env_client_secret = os.environ.get("CLIENT_SECRET")
    print('=' * 30)
    print('env_client_id: ', env_client_id)
    print('env_client_secret: ', env_client_secret[0:5] if env_client_secret else '')

    secret_id = sys.argv[1]
    lifetime_seconds = 7889400

    if len(sys.argv) == 3:
        try:
            lifetime_seconds = int(sys.argv[2])
            if lifetime_seconds <= 0:
                raise ValueError
        except ValueError:
            print("Erro: 'lifetime_seconds' deve ser um número inteiro positivo.")
            sys.exit(1)

    process_secret(secret_id, lifetime_seconds=lifetime_seconds)

if __name__ == "__main__":
    main()
