import subprocess
import json
import sys
import datetime
import os
import boto3
import requests
import unicodedata
from dotenv import load_dotenv

def bold(text):
    """
    Converte texto para caracteres Unicode 'Mathematical Bold', que sobrevivem
    ao copy-paste em clientes de email (Outlook, Gmail) sem precisar de HTML.
    O texto é normalizado em NFD para separar letras acentuadas em
    letra base + acento combinante: a letra base fica em negrito e o
    acento original é preservado, evitando peso misto na palavra.
    """
    text = unicodedata.normalize("NFD", str(text))
    result = []
    for ch in text:
        code = ord(ch)
        if 0x41 <= code <= 0x5A:        # A-Z
            result.append(chr(0x1D400 + code - 0x41))
        elif 0x61 <= code <= 0x7A:      # a-z
            result.append(chr(0x1D41A + code - 0x61))
        elif 0x30 <= code <= 0x39:      # 0-9
            result.append(chr(0x1D7CE + code - 0x30))
        else:
            result.append(ch)
    return "".join(result)

def run_command(command, stdin_value=None):
    """
    Executa um comando (lista de argumentos, sem shell) e retorna a saída.
    Valores sensíveis devem ser passados via stdin_value, nunca como argumento,
    para não ficarem visíveis na lista de processos.
    Lança uma exceção em caso de erro.
    """
    result = subprocess.run(command, input=stdin_value, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        raise Exception(f"Erro ao executar comando:\n{' '.join(command)}\n{result.stderr}")
    return result.stdout

def update_databricks_secret(scope, secret_name, token_value, workspace):
    """
    Atualiza uma secret no Databricks via CLI.
    """
    print(f"🔐 Atualizando secret '{secret_name}' no scope '{scope}' do Databricks workspace {workspace} ...")
    command = ["databricks", "secrets", "put-secret", scope, secret_name, "-p", workspace]
    run_command(command, stdin_value=token_value)
    print("✅ Secret atualizada no Databricks com sucesso.")

def update_aws_secret(secret_id, secret_dict):
    """
    Atualiza a secret no AWS Secrets Manager com o novo dicionário completo.
    """
    print("📦 Atualizando secret no AWS Secrets Manager...")
    client = boto3.client("secretsmanager")
    client.update_secret(
        SecretId=secret_id,
        SecretString=json.dumps(secret_dict)
    )
    print(f"✅ Secret '{secret_id}' atualizada com sucesso na AWS.")

def process_secret(secret_id):
    """
    Processo principal de renovação da credencial.
    """
    client = boto3.client("secretsmanager")

    # 1. Busca secret existente
    print(f"🔎 Buscando secret no AWS Secrets Manager: {secret_id}")
    secret_value = client.get_secret_value(SecretId=secret_id)
    secret_dict = json.loads(secret_value["SecretString"])

    # Salva valores antigos (se existirem)
    old_token = secret_dict.get("token")
    old_expiration = secret_dict.get("expiration_time")

    # --- VALIDAÇÃO DA EXPIRAÇÃO DE TOKEN ---
    if old_token and old_expiration:
        try:
            # Converte a string YYYY-MM-DD para um objeto date
            expiration_date_obj = datetime.datetime.strptime(old_expiration, "%Y-%m-%d").date()
            # Pega a data de hoje (em UTC, para consistência)
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
            # Caso a data esteja em formato inválido, força a renovação
            print(f"⚠️ Não foi possível analisar a data de expiração antiga ('{old_expiration}'). Prosseguindo com a renovação.")
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
    
    # Novos campos para lógica OAuth
    auth_method = secret_dict.get("sp_auth_method", "basic")

    lifetime_seconds = 7889400

    # 3. Fluxo Condicional de Geração de Token/Secret
    if auth_method == "oauth_m2m":
        print("\n🚀 Iniciando fluxo de renovação OAuth M2M (Account API)...")
        
        # Lendo credenciais das variáveis de ambiente
        env_client_id = os.environ.get("CLIENT_ID")
        env_client_secret = os.environ.get("CLIENT_SECRET")
        account_id = os.environ.get("ACCOUNT_ID")

        if not env_client_id or not env_client_secret or not account_id:
            raise Exception("ERRO: As variáveis de ambiente CLIENT_ID, CLIENT_SECRET e ACCOUNT_ID não foram encontradas. Elas são obrigatórias para gerar o token Account-Level.")

        # Passo 1 - Gerar token account-level usando as variáveis de ambiente
        print("   ↳ 1. Gerando token account-level...")
        token_url = f"https://accounts.cloud.databricks.com/oidc/accounts/{account_id}/v1/token"
        
        # O parâmetro 'auth' do requests simula exatamente o comportamento do '--user "$CLIENT_ID:$CLIENT_SECRET"' no cURL
        token_resp = requests.post(
            token_url,
            auth=(env_client_id, env_client_secret),
            data={"grant_type": "client_credentials", "scope": "all-apis"},
            timeout=30
        )
        token_resp.raise_for_status()
        oauth_token = token_resp.json()["access_token"]

        # Passo 2 - Obter o internal_id (Resource ID) do Service Principal a ser renovado
        print("   ↳ 2. Obtendo o Service Principal ID interno via SCIM...")
        scim_url = f"https://accounts.cloud.databricks.com/api/2.0/accounts/{account_id}/scim/v2/ServicePrincipals"
        scim_resp = requests.get(
            scim_url,
            headers={"Authorization": f"Bearer {oauth_token}"},
            params={"filter": f"applicationId eq '{application_id}'"},
            timeout=30
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
            json={"lifetime": f"{lifetime_seconds}s"},
            timeout=30
        )
        secrets_resp.raise_for_status()
        
        # Coleta a nova secret
        token_value = secrets_resp.json()["secret"]
        
        # Calcula a nova data de expiração
        expiry_datetime = datetime.datetime.now(datetime.UTC) + datetime.timedelta(seconds=lifetime_seconds)
        expiration_date = expiry_datetime.strftime("%Y-%m-%d")

    else:
        # Fluxo OBO Token (Basic)
        print("\n🔧 Gerando novo token OBO com Databricks CLI...")
        command = ["databricks", "token-management", "create-obo-token", application_id, "--lifetime-seconds", str(lifetime_seconds), "-p", workspace]
        output = run_command(command)
        token_data = json.loads(output)

        token_value = token_data["token_value"]
        expiry_time_ms = token_data["token_info"]["expiry_time"]
        expiration_date = datetime.datetime.fromtimestamp(expiry_time_ms / 1000, tz=datetime.UTC).strftime("%Y-%m-%d")


    # 4. Atualiza valores comuns na secret local
    update_time = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d")
    secret_dict["token"] = token_value
    secret_dict["expiration_time"] = expiration_date
    secret_dict["update_time"] = update_time

    # 5. Atualiza secret na AWS
    update_aws_secret(secret_id, secret_dict)

    # 6. Atualiza secret no Databricks, se aplicável
    if scope and secret_name:
        update_databricks_secret(scope, secret_name, token_value, workspace_scope or workspace)
    else:
        print("ℹ️ Campos 'scope' e/ou 'secret' não encontrados. O Secret Scope do Databricks não será atualizado.")

    # 7. Resumo
    print(f"\n📋 Resumo da atualização:")
    print(f"🔒 Método utilizado: {auth_method}")
    if old_token:
        print(f"🔑 Token/Secret antigo: {old_token[:5]}... (ocultado)")
    if old_expiration:
        print(f"📅 Expiração antiga: {old_expiration}")

    print(f"\n🔑 Novo Token/Secret: {token_value[:5]}... (ocultado)")
    print(f"📅 Expira em: {expiration_date}")
    print(f"🕒 Atualizado em: {update_time}")
    print(f"✉️ Email: {email_address or 'N.A'}")
    
    # 8. Texto adicional
    if email_address:
        sql_warehouse_name = secret_id.split("/")[-1]

        print(f"""
[ IMPORTANTE ] Atualização de Credenciais SQL Warehouse Databricks - {sql_warehouse_name}
Prezado(a),
          
Este email contém suas novas credenciais de acesso para o SQL Warehouse \033[1m{sql_warehouse_name}\033[0m no Databricks.

Este email contém suas novas credenciais de acesso para o SQL Warehouse {sql_warehouse_name}

Sua credencial antiga, associada ao Application ID {application_id} irá vencer em {old_expiration}.

Application ID: {application_id}
Nova Credencial: {token_value}
Validade: {expiration_date}

Por favor, atualize suas configurações para usar a nova credencial antes da data de expiração da antiga para evitar interrupções.
{single_email_warning}
Em caso de dúvidas, estamos à disposição.

Atenciosamente,
""")

def main():
    if len(sys.argv) != 2:
        print("Uso: python update_databricks_secret.py <nome_da_secret>")
        sys.exit(1)

    secret_id = sys.argv[1]
    process_secret(secret_id)

if __name__ == "__main__":
    main()
