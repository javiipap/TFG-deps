#!/usr/bin/env bash

# --- Funciones de Mensajería ---

# Función para mostrar un mensaje de error y salir
exit_on_error() {
    stop_spinner # Asegurarse de que el spinner se detenga antes de salir por error
    echo -e "\n❌ Error: $1" >&2
    exit 1
}

# Función para mostrar mensajes informativos
log_info() {
    echo -e "💡 Info: $1" # Añadido -e para interpretar secuencias de escape
}

# Función para mostrar mensajes de éxito
log_success() {
    echo -e "✅ Éxito: $1"
}

if [ "$#" -lt 2 ]; then
    log_info "Uso: $0 <tipo_libreria> <out_dir>"
    log_info "Tipos de libreria disponibles: glib, musl"
    exit 1
fi

# --- Configuración Inicial ---
DEFAULT_DIR="../web/src/lib/pkg"
TARGET_DIR="" # Usaremos esta variable para el directorio final
NODE_FILE="server_utilities.linux-x64-gnu.node"

if [ "$1" == "musl" ]; then
    NODE_FILE="server_utilities.linux-x64-musl.node"
    log_info "Configurado para compilar con: musl"
elif [ "$1" == "glib" ]; then
    NODE_FILE="server_utilities.linux-x64-gnu.node"
    log_info "Configurado para compilar con: glib (GNU)"
else
    log_info "Error: Tipo de librería no válido. Usa 'glib' o 'musl'."
    exit 1
fi


# --- Procesamiento de Argumentos ---
if [ -n "$2" ]; then
    TARGET_DIR="$2"
    log_info "Directorio de destino especificado: $TARGET_DIR"
else
    TARGET_DIR="$DEFAULT_DIR"
    log_info "No se especificó un directorio de destino. Usando el predeterminado: $TARGET_DIR"
fi

# --- Función de Spinner de Carga ---

_spinner_pid=""
_spinner_chars="/-\|"

# Inicia un spinner en segundo plano
start_spinner() {
    local i=0
    local delay=0.1
    local message="$1" # Mensaje a mostrar junto al spinner

    # Mueve el cursor a la columna 0, limpia la línea, y lo mueve de nuevo a la columna 0
    # Imprime el mensaje y el primer carácter del spinner.
    printf "\r${_spinner_chars:$((i++ % ${#_spinner_chars})):1} ${message}"

    # Bucle infinito que se ejecuta en segundo plano
    while true; do
        printf "\r${_spinner_chars:$((i++ % ${#_spinner_chars})):1} ${message}"
        sleep $delay
    done &
    _spinner_pid=$! # Guarda el PID del proceso del spinner
    disown          # Desvincula el proceso del shell para que no se mate al salir del script principal (si no se hace stop_spinner)
}

# Detiene el spinner y limpia la línea
stop_spinner() {
    if [ -n "$_spinner_pid" ]; then
        kill "$_spinner_pid" >/dev/null 2>&1 # Mata el proceso del spinner
        wait "$_spinner_pid" 2>/dev/null     # Espera a que termine (opcional, para evitar zombies en algunos casos)
        _spinner_pid=""                      # Limpia la variable del PID
    fi
    # Limpia la línea donde estaba el spinner (Mueve el cursor a la columna 0, limpia hasta el final de la línea)
    printf "\r\033[K"
}

# --- Manejo de Señales (Ctrl + C) ---

# Función que se ejecutará al recibir SIGINT (Ctrl + C)
cleanup_on_interrupt() {
    echo -e "\n🛑 Proceso interrumpido por el usuario." >&2
    stop_spinner # Asegúrate de limpiar el spinner
    exit 1       # Salir del script con un código de error
}

# Configura el trap: cuando se reciba SIGINT, llama a cleanup_on_interrupt
trap cleanup_on_interrupt SIGINT

# --- Nueva Función: Modificar index.js ---

# Modifica el archivo index.js para simplificar la carga del binding nativo
modify_server_index_js() {
    local index_file="$1"
    local start_pattern="const { generateElgamalKeypair, encryptVote, eccEncrypt, eccDecrypt, createRequest, generateRsaKeypair, sign, unblind, verify } = nativeBinding"
    local new_header="const nativeBinding = require('./$NODE_FILE');\nif (!nativeBinding) {\n  throw Error(\"Couldn't load binary lib\");\n}"

    log_info "Modificando '$index_file' para simplificar la carga del binding nativo..."

    if [ ! -f "$index_file" ]; then
        exit_on_error "El archivo '$index_file' no fue encontrado para modificar."
    fi

    # Usar awk para procesar el archivo y sobrescribirlo in-place (o a un temp y luego renombrar)
    # Para mayor seguridad, creamos un archivo temporal y luego lo movemos
    awk -v new_header="$new_header" -v start_pattern="$start_pattern" '
    BEGIN {
        # Imprimir la nueva cabecera al principio
        print new_header
        found_pattern = 0
    }
    {
        # Si encontramos el patrón, activamos la bandera para imprimir las líneas siguientes
        if ($0 ~ start_pattern) {
            found_pattern = 1
        }
        # Si la bandera está activada, imprimimos la línea actual
        if (found_pattern) {
            print
        }
    }' "$index_file" > "${index_file}.tmp" || exit_on_error "Fallo al procesar '$index_file'."

    mv "${index_file}.tmp" "$index_file" || exit_on_error "Fallo al renombrar el archivo temporal a '$index_file'."
    log_success "'$index_file' modificado exitosamente."
}

# --- Validación del Directorio de Destino ---
PARENT_DIR=$(dirname "$TARGET_DIR")
if [ ! -d "$PARENT_DIR" ]; then
    exit_on_error "El directorio padre para '$TARGET_DIR' no existe: '$PARENT_DIR'. Por favor, asegúrate de que la ruta base sea correcta."
fi

# --- Creación de Directorios ---
log_info "Creando directorios necesarios en '$TARGET_DIR'..."
mkdir -p "$TARGET_DIR/client_utilities" "$TARGET_DIR/server_utilities" || exit_on_error "No se pudieron crear los directorios necesarios."
log_success "Directorios creados exitosamente."

# --- Compilación de Componentes ---

log_info "Iniciando compilación de componentes..."

# Compilar primitivas criptográficas
start_spinner "Compilando primitivas criptográficas..."
cd primitives || { stop_spinner; exit_on_error "No se pudo cambiar al directorio 'primitives'."; }
cargo build || { stop_spinner; exit_on_error "Fallo al compilar 'primitives'. Verifica el log de Cargo."; }
cd .. || { stop_spinner; exit_on_error "No se pudo regresar al directorio principal."; }
stop_spinner
log_success "Primitivas criptográficas compiladas."

# Compilar librería para el cliente
start_spinner "Compilando librería para el cliente (wasm-pack)..."
cd client_lib || { stop_spinner; exit_on_error "No se pudo cambiar al directorio 'client_lib'."; }
wasm-pack build --target web || { stop_spinner; exit_on_error "Fallo al compilar 'client_lib' con wasm-pack. Asegúrate de que wasm-pack esté instalado y configurado."; }
cd .. || { stop_spinner; exit_on_error "No se pudo regresar al directorio principal."; }
stop_spinner
log_success "Librería del cliente compilada."

# Compilar librería para el servidor
start_spinner "Compilando librería para el servidor (Node.js)..."
cd server_lib || { stop_spinner; exit_on_error "No se pudo cambiar al directorio 'server_lib'."; }
yarn build || { stop_spinner; exit_on_error "Fallo al compilar 'server_lib' con Yarn. Asegúrate de que Yarn y las dependencias estén instaladas."; }

# --- Llamada a la nueva función para modificar index.js ---
modify_server_index_js "index.js" # Modifica el index.js recién compilado

cd .. || { stop_spinner; exit_on_error "No se pudo regresar al directorio principal."; }
stop_spinner
log_success "Librería del servidor compilada y archivo index.js modificado."


# --- Copia de Librerías ---
log_info "Copiando librerías al entorno de desarrollo..."

# Copiar librería del servidor
SERVER_SOURCE_DIR="server_lib"
SERVER_DEST_DIR="$TARGET_DIR/server_utilities"

# Copiar todos los archivos excepto server_utilities.linux-x64-{BUILD}.node
# (ya que este es el que se carga directamente ahora)
# De hecho, según tu instrucción previa, solo quieres copiar los listados:
cp "$SERVER_SOURCE_DIR/$NODE_FILE" "$SERVER_DEST_DIR/" || exit_on_error "Fallo al copiar '$NODE_FILE'."
cp "$SERVER_SOURCE_DIR/index.d.ts" "$SERVER_DEST_DIR/" || exit_on_error "Fallo al copiar 'index.d.ts'."
cp "$SERVER_SOURCE_DIR/index.js" "$SERVER_DEST_DIR/" || exit_on_error "Fallo al copiar 'index.js'."
cp "$SERVER_SOURCE_DIR/package.json" "$SERVER_DEST_DIR/" || exit_on_error "Fallo al copiar 'package.json'."
log_success "Librería del servidor copiada."

# Copiar librería del cliente
CLIENT_SOURCE_DIR="client_lib/pkg"
CLIENT_DEST_DIR="$TARGET_DIR/client_utilities"
cp -r "$CLIENT_SOURCE_DIR/." "$CLIENT_DEST_DIR/" || exit_on_error "Fallo al copiar archivos de 'client_lib/pkg'."
log_success "Librería del cliente copiada."

log_success "Proceso completado exitosamente. Todas las librerías están en '$TARGET_DIR'."
