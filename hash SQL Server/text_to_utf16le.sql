/*
 @Function: public.text_to_utf16le
 @Creation Date: 15/02/2026
 @Description: Convierte texto plano a una representación bytea en formato UTF-16LE 
                (necesario para compatibilidad de hashing con MSSQL).
 @Parameters:
   - @p_txt (text): Cadena de texto a convertir.
 @Returns: bytea - Representación binaria en UTF-16LE.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 15/02/2026
 @Change: Creación inicial siguiendo estándares corporativos.
 @Author: CR0NYM3X
*/


---------------- CODE ----------------
CREATE OR REPLACE FUNCTION public.text_to_utf16le(
    p_txt text
) 
RETURNS bytea 
AS $func$
BEGIN
    /* Optimización: Convierte a hex, intercala '00' cada 2 caracteres (1 byte)
       y decodifica de vuelta a bytea.
    */
    RETURN pg_catalog.decode(
        regexp_replace(
            pg_catalog.encode(p_txt::bytea, 'hex'), 
            '(..)', 
            '\100', 
            'g'
        ), 
        'hex'
    );
END;
$func$ 
LANGUAGE plpgsql 
IMMUTABLE 
STRICT;



---------------- COMMENT ----------------
COMMENT ON FUNCTION public.text_to_utf16le(text) IS
'Convierte texto a formato binario UTF-16LE.
- Parámetros: p_txt (text)
- Retorno: bytea
- Volatilidad: IMMUTABLE
- Seguridad: SECURITY INVOKER
- Notas: Utiliza expresiones regulares para intercalar bytes nulos.';


-- Restringir acceso general
-- REVOKE EXECUTE ON FUNCTION public.text_to_utf16le(text) FROM PUBLIC;

---------------- EXAMPLE USAGE ----------------
-- SELECT public.text_to_utf16le('jose123');


