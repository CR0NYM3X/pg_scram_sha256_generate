

/*
 @Function: public.pg_mssql_sha512_generate
 @Creation Date: 15/02/2026
 @Description: Genera hashes compatibles con Microsoft SQL Server. 
                Soporta formato moderno (0x0200 - SHA512) y antiguo (0x0100 - SHA1).
 @Parameters:
   - @p_password (text): Contraseña en texto plano.
   - @p_version (text): Versión del hash ('0x0200' o '0x0100'). Default '0x0200'.
 @Returns: text - String hexadecimal con prefijo 0x.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 15/02/2026
 @Change: Se añade soporte paramétrico para versiones antiguas (SHA1) = 0x0100  y modernas (SHA512) = 0x0200.
 @Author: CR0NYM3X
*/


 create EXTENSION pgcrypto ;

---------------- CODE ----------------
CREATE OR REPLACE FUNCTION public.pg_mssql_sha512_generate(
    p_password text,
    p_version  text DEFAULT '0x0200'
)
RETURNS text 
AS $func$
DECLARE
    -- Variables de control
    v_algo          text;
    v_header_hex    text;
    
    -- Variables de procesamiento
    v_salt          bytea;
    v_pwd_utf16le   bytea;
    v_hashed_part   bytea;
    v_final_hash    bytea;
BEGIN
    -- 1. Identificar algoritmo y validar versión
    IF p_version = '0x0200' THEN
        v_algo := 'sha512';
        v_header_hex := '0200';
    ELSIF p_version = '0x0100' THEN
        v_algo := 'sha1';
        v_header_hex := '0100';
    ELSE
        RAISE EXCEPTION 'Versión de hash MSSQL no soportada: %', p_version
            USING HINT = 'Use 0x0200 para SHA-512 o 0x0100 para SHA-1';
    END IF;

    -- 2. Generar Salt (4 bytes estándar en todas las versiones de MSSQL)
    v_salt := public.gen_random_bytes(4);
    
    -- 3. Convertir password a UTF-16LE
    v_pwd_utf16le := public.text_to_utf16le(p_password);
    
    -- 4. Calcular Digest dinámico según la versión
    v_hashed_part := public.digest(v_pwd_utf16le || v_salt, v_algo);
    
    -- 5. Concatenar: Header + Salt + Hash
    v_final_hash := pg_catalog.decode(v_header_hex, 'hex') || v_salt || v_hashed_part;
    
    -- 6. Retorno formateado
    RETURN '0x' || pg_catalog.upper(pg_catalog.encode(v_final_hash, 'hex'));
END;
$func$ 
LANGUAGE plpgsql 
STABLE
SECURITY DEFINER;

-- Ajuste de seguridad search_path
ALTER FUNCTION public.pg_mssql_sha512_generate(text, text) 
SET search_path TO public, pg_temp;



---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_mssql_sha512_generate(text, text) IS
'Genera hashes estilo MSSQL para migración de credenciales.
- Parámetros: p_password (texto), p_version (0x0200=SHA512, 0x0100=SHA1)
- Retorno: text (hexadecimal prefijado con 0x)
- Volatilidad: STABLE
- Seguridad: SECURITY DEFINER con search_path fijo.
- Notas: Requiere extensión pgcrypto y helper text_to_utf16le.';


REVOKE ALL ON FUNCTION public.pg_mssql_sha512_generate(text, text) FROM PUBLIC;



---------------- EXAMPLE USAGE ----------------
-- Generar hash moderno (Default - SQL 2012+)
-- SELECT public.pg_mssql_sha512_generate('admin123'); 


-- Generar hash antiguo (SQL 2000/2005/2008)
-- SELECT public.pg_mssql_sha512_generate('admin123', '0x0100');






