/*
 @Function: public.pg_verify_scram_sha256
 @Creation Date: 09/02/2026
 @Description: Valida si una contraseña en texto plano coincide con un hash SCRAM-SHA-256.
 @Parameters:
   - @p_password (text): Contraseña ingresada por el usuario.
   - @p_stored_hash (text): Hash completo guardado en la DB (formato SCRAM-SHA-256$...).
 @Returns: boolean - TRUE si la contraseña es correcta, FALSE de lo contrario.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 09/02/2026
 @Change: Creación inicial siguiendo el estándar RFC 7677.
 @Author: CR0NYM3X
*/


---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_verify_scram_sha256(text, text) IS
'Verifica contraseñas contra hashes SCRAM-SHA-256.
- Parámetros: p_password (input), p_stored_hash (hash de la DB).
- Retorno: boolean.
- Seguridad: SECURITY INVOKER.
- Notas: Extrae automáticamente salt e iteraciones del hash.';

-- DROP FUNCTION public.pg_verify_scram_sha256(text, text);
CREATE OR REPLACE FUNCTION public.pg_verify_scram_sha256(
    p_password    text, 
    p_stored_hash text
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
AS $func$
DECLARE
    -- Variables de extracción (v_)
    v_parts          text[];
    v_iters_salt     text[];
    v_keys           text[];
    v_iterations     integer;
    v_salt_b64       text;
    v_stored_key_b64 text;
    
    -- Variables de cálculo (v_)
    v_salt_bin       bytea;
    v_salted_pw      bytea;
    v_client_key     bytea;
    v_calc_stored_bin bytea;
    v_calc_stored_b64 text;
    
    -- PBKDF2
    v_u              bytea;
    v_t              bytea;
    v_i              integer;
    v_j              integer;
BEGIN
    -- 1. Descomponer el hash almacenado
    -- Formato: SCRAM-SHA-256$4096:salt$stored_key:server_key
    v_parts      := string_to_array(p_stored_hash, '$');
    v_iters_salt := string_to_array(v_parts[2], ':');
    v_keys       := string_to_array(v_parts[3], ':');
    
    v_iterations     := v_iters_salt[1]::integer;
    v_salt_b64       := v_iters_salt[2];
    v_stored_key_b64 := v_keys[1];
    
    v_salt_bin := decode(v_salt_b64, 'base64');

    -- 2. Re-generar PBKDF2 con la contraseña ingresada y la salt extraída
    v_u := public.hmac(v_salt_bin || E'\\x00000001'::bytea, p_password::bytea, 'sha256');
    v_t := v_u; 
    
    FOR v_i IN 2..v_iterations LOOP
        v_u := public.hmac(v_u, p_password::bytea, 'sha256');
        FOR v_j IN 0..31 LOOP
            v_t := set_byte(v_t, v_j, get_byte(v_t, v_j) # get_byte(v_u, v_j));
        END LOOP;
    END LOOP;
    
    v_salted_pw := v_t;

    -- 3. Calcular la StoredKey: SHA256(HMAC(SaltedPassword, "Client Key"))
    v_client_key      := public.hmac('Client Key'::bytea, v_salted_pw, 'sha256');
    v_calc_stored_bin := public.digest(v_client_key, 'sha256');
    v_calc_stored_b64 := regexp_replace(encode(v_calc_stored_bin, 'base64'), E'\\s', '', 'g');

    -- 4. Comparación final
    RETURN (v_calc_stored_b64 = v_stored_key_b64);

EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE; -- Ante cualquier error de formato, la contraseña no es válida
END;
$func$;

ALTER FUNCTION public.pg_verify_scram_sha256(text, text) SET search_path TO public, pg_temp;

REVOKE EXECUTE ON FUNCTION public.pg_verify_scram_sha256(text, text) FROM PUBLIC;


-- select * from public.fn_util_verify_scram_sha256('password123', 'SCRAM-SHA-256$10000:vk2Y3Dp2jD6XCdcI3cqmMQ==$2J2PAu6w1rOBiy+F5JOjY3i94ZIpYGCKfkSphzf6RBk=:gDctN/Chn0if2DlAWKTl5X9JBX89KZzMSk1TIcrs9HI=');



