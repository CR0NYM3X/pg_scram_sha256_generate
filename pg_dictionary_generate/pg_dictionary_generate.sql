DROP FUNCTION security.pg_dictionary_generate ( text[],boolean,int);
CREATE OR REPLACE FUNCTION security.pg_dictionary_generate (
    p_keywords      text[],
    p_persistir     boolean DEFAULT false,
    p_max_palabras  int DEFAULT 1000
)
RETURNS TABLE(password_generated text) 
LANGUAGE plpgsql
AS $$
DECLARE
    v_defaults  text[];
    v_simbolos  text[];
    v_años      text[];
    v_nums      text[];
BEGIN
    v_defaults := ARRAY['admin','root','user','pass','temp','password'];
    v_simbolos := ARRAY['.', '!', '@', '#', '$', '*', '_','?'];
    v_años     := ARRAY['2022', '2023', '2024', '2025', '2026', '2005'];
    v_nums     := ARRAY['123', '123456', '1', '7', '01'];

    IF p_persistir THEN
        DROP TABLE IF EXISTS security.diccionario_generado;
        CREATE UNLOGGED TABLE security.diccionario_generado (word text PRIMARY KEY);
    END IF;

    RETURN QUERY
    WITH RECURSIVE 
    base_input AS (
        SELECT unnest(p_keywords) as k
    ),
    mutations AS (
        -- Asignamos prioridad a las mutaciones base
        SELECT DISTINCT val, priority FROM (
            SELECT k as val, 1 as priority FROM base_input -- Original (Máxima prioridad)
            UNION
            SELECT upper(k), 1 FROM base_input             -- MAYÚSCULAS (Máxima prioridad)
            UNION
            SELECT k || '123', 1 FROM base_input           -- palabra123 (Máxima prioridad)
            UNION
            SELECT reverse(k), 2 FROM base_input
            UNION
            SELECT string_agg(CASE WHEN random() > 0.5 THEN upper(ch) ELSE lower(ch) END, '' ORDER BY pos), 2
            FROM base_input, regexp_split_to_table(k, '') WITH ORDINALITY as t(ch, pos) GROUP BY k
            UNION
            SELECT string_agg(ch || ch, '' ORDER BY pos), 2
            FROM base_input, regexp_split_to_table(k, '') WITH ORDINALITY as t(ch, pos) GROUP BY k
            UNION
            SELECT translate(lower(k), 'aeioslbt', '43105187'), 2 FROM base_input
        ) m
    ),
    intelligent_combinations AS (
        -- Mantenemos la lógica de combinaciones pero heredamos/asignamos prioridad
        SELECT val, priority FROM mutations
        UNION ALL
        SELECT 
            CASE floor(random() * 6)::int
                WHEN 0 THEN m.val || n                             
                WHEN 1 THEN m.val || s || n || s                   
                WHEN 2 THEN m.val || a || s || n                   
                WHEN 3 THEN m.val || s                             
                WHEN 4 THEN m.val || s || d || s || a || s         
                ELSE m.val || s || n                               
            END as val,
            3 as priority -- Combinaciones complejas (Menor prioridad)
        FROM mutations m
        CROSS JOIN unnest(v_simbolos) s
        CROSS JOIN unnest(v_nums) n
        CROSS JOIN unnest(v_años) a
        CROSS JOIN unnest(v_defaults) d
        LIMIT p_max_palabras * 10
    ),
    final_processing AS (
        -- Seleccionamos el valor y la mínima prioridad encontrada para cada uno
        SELECT val, MIN(priority) as best_priority 
        FROM intelligent_combinations 
        WHERE length(val) >= 3
        GROUP BY val
    )
    -- ORDENADO INTELIGENTE:
    -- Primero por prioridad (1 antes que 3)
    -- Luego de forma aleatoria dentro de la misma prioridad
    SELECT val FROM final_processing
    ORDER BY best_priority ASC, random()
    LIMIT p_max_palabras;

    IF p_persistir THEN
        INSERT INTO security.diccionario_generado (word)
        SELECT security.pg_dictionary_generate (p_keywords, false, p_max_palabras)
        ON CONFLICT DO NOTHING;
    END IF;
END;
$$;


SELECT password_generated FROM security.pg_dictionary_generate (
    p_keywords := ARRAY[ 'perro'], 
    p_persistir := false, 
    p_max_palabras := 500
);


