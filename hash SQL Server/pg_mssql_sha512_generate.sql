CREATE OR REPLACE FUNCTION text_to_utf16le(txt text) 
RETURNS bytea AS $$
BEGIN
    -- Convierte el texto a bytes y añade un byte nulo (\x00) después de cada carácter
    RETURN decode(regexp_replace(encode(txt::bytea, 'hex'), '(..)', '\100', 'g'), 'hex');
END;
$$ LANGUAGE plpgsql IMMUTABLE;



CREATE OR REPLACE FUNCTION pg_mssql_sha512_generate(password text)
RETURNS text AS $$
DECLARE
    salt bytea;
    password_utf16le bytea;
    hashed_part bytea;
    final_hash bytea;
BEGIN
    salt := gen_random_bytes(4);
    password_utf16le := text_to_utf16le(password);
    
    -- SQL Server 2012+ usa SHA-512
    hashed_part := digest(password_utf16le || salt, 'sha512');
    
    final_hash := decode('0200', 'hex') || salt || hashed_part;
    
    RETURN '0x' || upper(encode(final_hash, 'hex'));
END;
$$ LANGUAGE plpgsql;

-- select * from pg_mssql_sha512_generate('jose123');

