/*
 @Function: public.pg_md5_verify
 @Creation Date: 09/02/2026
 @Description: Verifica si una contraseña coincide con un hash MD5 almacenado.
 @Parameters:
   - @p_username (text): Nombre del rol/usuario (salt en MD5).
   - @p_password (text): Contraseña en texto plano a validar.
   - @p_stored_hash (text): Hash guardado en pg_authid (formato md5...).
 @Returns: boolean - TRUE si el hash generado coincide con el almacenado.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 09/02/2026
 @Change: Adaptación a plantilla corporativa y nomenclatura p_/v_.
 @Author: CR0NYM3X
*/


CREATE OR REPLACE FUNCTION public.pg_md5_verify(
    p_username    text,
    p_password    text,
    p_stored_hash text
)
RETURNS boolean
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
AS $func$
DECLARE
    -- Variables locales (v_)
    v_hash_generated text;
BEGIN
    -- 1. Validaciones mínimas de entrada
    IF p_username IS NULL OR p_password IS NULL OR p_stored_hash IS NULL THEN
        RETURN FALSE;
    END IF;

    -- 2. Generación del hash con el formato esperado por PostgreSQL
    -- Se concatena el prefijo 'md5' con el resultado de md5(pass + user)
    v_hash_generated := 'md5' || pg_catalog.md5(p_password || p_username);

    -- 3. Comparación y retorno
    RETURN v_hash_generated = p_stored_hash;

EXCEPTION
    WHEN OTHERS THEN
        -- Ante cualquier error de procesamiento, se retorna falso por seguridad
        RETURN FALSE;
END;
$func$;



---------------- COMMENT ----------------
COMMENT ON FUNCTION public.pg_md5_verify(text, text, text) IS
'Verifica integridad de credenciales MD5 heredadas.
- Parámetros: p_username, p_password, p_stored_hash.
- Retorno: boolean.
- Volatilidad: STABLE.
- Seguridad: SECURITY INVOKER con search_path restringido.';



-- Seguridad: Fija search_path para evitar hijacking de la función md5()
ALTER FUNCTION public.pg_md5_verify(text, text, text) SET search_path TO public, pg_temp;

---------------- SECURITY REVOKE ----------------
REVOKE EXECUTE ON FUNCTION public.pg_md5_verify(text, text, text) FROM PUBLIC;


--- SELECT * from  public.pg_md5_verify('user_test', 'password123', 'md5a55cc73725a729b561ecfc4984d922a9');
