
/*
 @Function: security.fn_generar_diccionario_pentest
 @Creation Date: 15/02/2026
 @Description: Motor de generación de diccionarios (Wordlists) para ataques de fuerza bruta 
               y auditoría de robustez de credenciales. La función aplica una lógica de 
               "Multi-Pasada" balanceada para transformar palabras clave simples en miles de 
               combinaciones complejas que simulan patrones reales de usuarios humanos.
 
 @Niveles de Profundidad (p_profundidad):
 | Nivel | Tipo de Ataque | Lógica de Combinación | Ejemplo (Keyword: Soporte) |
 |-------|----------------|-----------------------|----------------------------|
 | 1     | Básico         | Solo símbolo al FINAL. Patrón humano estándar. | Soporte@2026 |
 | 2     | Medio          | Habilita PREFIJOS. Símbolo al INICIO (Evasión). | @Soporte2026 |
 | 3     | Agresivo       | Repite ciclos de combinaciones y permutaciones. | !Soporte2024 |

 @Parameters:
   - @p_keywords (text[]): Array de términos base (semillas). Raíces de construcción.
   - @p_persistir (boolean): TRUE para insertar en 'security.diccionario_generado' (UNLOGGED).
   - @p_anio_inicio (int) & @p_anio_fin (int): Ventana temporal para sufijos numéricos.
   - @p_profundidad (int): Nivel de agresividad (1: Sufijos, >1: Prefijos/Permutaciones).
   - @p_max_palabras (int): Techo máximo de registros (Reparto equitativo por keyword).
   - @p_shuffle (boolean): TRUE para mezclar resultados aleatoriamente (Evasión IDS).
 @Returns: TABLE(word text) - Set de datos dinámico con variaciones.
 @Author: CR0NYM3X
 ---------------- HISTORY ----------------
 @Date: 15/02/2026
 @Change: Integración de tabla de niveles de profundidad y lógica de Shuffle balanceada.
 @Author: CR0NYM3X
*/



-- DROP FUNCTION security.fn_generar_diccionario_pentest(text[],boolean,int,int,int,int,boolean);

CREATE OR REPLACE FUNCTION security.fn_generar_diccionario_pentest(
    p_keywords     text[],
    p_persistir    boolean DEFAULT false,
    p_anio_inicio  int DEFAULT extract(year from current_date),
    p_anio_fin     int DEFAULT extract(year from current_date) + 1,
    p_profundidad  int DEFAULT 1,
    p_max_palabras int DEFAULT 1000,
    p_shuffle      boolean DEFAULT false
)
RETURNS TABLE(word text) 
SET client_min_messages = 'notice'
LANGUAGE plpgsql
AS $func$
DECLARE
    -- Iteradores para control de bucles anidados
    v_kw           text;
    v_item         text;
    v_item_simbolo text;
    v_anio         int;
    v_ciclo        int;
    
    -- Variables para procesamiento de strings
    v_clean        text;
    v_leet         text;
    v_simbolos     text[] := ARRAY['!', '@', '#', '$', '*', '.', '_','?','¿'];
    
    -- Variables de monitoreo y balanceo
    v_total_global int := 0;      -- Contador total de palabras generadas
    v_total_kw     int := 0;      -- Contador de palabras generadas por la keyword actual
    v_max_por_kw   int;           -- Límite balanceado (p_max_palabras / cantidad de keywords)
BEGIN
    -- [1] INICIALIZACIÓN DE INFRAESTRUCTURA TÁCTICA
    -- Si p_shuffle es activo, recolectamos en tabla temporal para mezcla aleatoria
    IF p_shuffle THEN
        CREATE TEMP TABLE IF NOT EXISTS tt_shuffle_pentest (val text) ON COMMIT DROP;
        DELETE FROM tt_shuffle_pentest;
    END IF;

    -- Creación idempotente de tabla UNLOGGED para persistencia sin saturar logs de DB
    IF p_persistir THEN
        DROP TABLE IF EXISTS security.diccionario_generado;
        CREATE UNLOGGED TABLE security.diccionario_generado (word text PRIMARY KEY);
    END IF;

    -- Cálculo de cuota por palabra para asegurar representatividad de todas las keywords
    v_max_por_kw := CASE WHEN p_max_palabras > 0 THEN p_max_palabras / array_length(p_keywords, 1) ELSE 0 END;

    -- [2] NÚCLEO DE GENERACIÓN (ROUND ROBIN POR KEYWORD)
    FOREACH v_kw IN ARRAY p_keywords LOOP
        v_total_kw := 0; -- Reset de cuota para cada nueva semilla

        -- ETAPA A: PALABRA EXACTA (Prioridad 1 en diccionarios)
        word := v_kw;
        
        -- Registro en persistencia física si aplica
        IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
        
        -- Gestión de salida (Inmediata o hacia Buffer de Mezcla)
        IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); 
        ELSE RETURN NEXT; END IF;
        
        -- Incremento de contadores y validación de cuota
        v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
        IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN CONTINUE; END IF;

        -- Limpieza de caracteres: Eliminación de espacios para formar bloques compactos
        v_clean := replace(v_kw, ' ', '');
        
        -- ETAPA B: VARIACIONES DE CASE (Normalización de caja)
        FOR v_item IN SELECT unnest(ARRAY[lower(v_clean), upper(v_clean), initcap(v_clean)]) LOOP
            word := v_item; 
            IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
            
            IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); 
            ELSE RETURN NEXT; END IF;

            v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
            
            -- Salida temprana del bucle si se alcanza el límite balanceado
            IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN EXIT; END IF;

            -- ETAPA C: TRANSFORMACIÓN LEETSPEAK (Ofuscación alfanumérica)
            v_leet := translate(lower(v_item), 'aeiost', '431057');
            word := v_leet;
            IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
            
            IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); 
            ELSE RETURN NEXT; END IF;

            v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
            IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN EXIT; END IF;

            -- ETAPA D: PERMUTACIONES COMPLEJAS (Símbolos y Tiempo)
            -- El ciclo de profundidad define qué tanto iteramos sobre símbolos
            FOR v_ciclo IN 1..p_profundidad LOOP
                FOR v_anio IN p_anio_inicio..p_anio_fin LOOP
                    
                    -- Sub-Etapa: Palabra + Año
                    word := v_item || v_anio::text;
                    IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
                    
                    IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); 
                    ELSE RETURN NEXT; END IF;

                    v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
                    IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN EXIT; END IF;

                    -- Sub-Etapa: Inyección de Símbolos Especiales
                    FOREACH v_item_simbolo IN ARRAY v_simbolos LOOP
                        
                        -- AGRESIVIDAD EXTRA (NIVEL 2: Símbolos como prefijo)
                        IF v_ciclo >= 2 THEN
                            word := v_item_simbolo || v_item || v_anio::text;
                            IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
                            IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); ELSE RETURN NEXT; END IF;
                            v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
                            IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN EXIT; END IF;
                        END IF;

                        -- AGRESIVIDAD EXTRA (NIVEL 3: Símbolos como Infijo / Símbolo en medio)
                        -- Lógica: Palabra + Símbolo + Año (Ya contemplado abajo) + Inserción entre palabra y año
                        IF v_ciclo >= 3 THEN
                            -- Variante: Símbolo doble (Prefijo y Sufijo)
                            word := v_item_simbolo || v_item || v_item_simbolo || v_anio::text;
                            IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
                            IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); ELSE RETURN NEXT; END IF;
                            v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
                            IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN EXIT; END IF;
                        END IF;

                        -- Formato: PalabraSímboloAño (Sufijo estándar)
                        word := v_item || v_item_simbolo || v_anio::text;
                        IF p_persistir THEN INSERT INTO security.diccionario_generado VALUES (word) ON CONFLICT DO NOTHING; END IF;
                        
                        IF p_shuffle THEN INSERT INTO tt_shuffle_pentest VALUES (word); 
                        ELSE RETURN NEXT; END IF;

                        v_total_global := v_total_global + 1; v_total_kw := v_total_kw + 1;
                        IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) OR (p_max_palabras > 0 AND v_total_global >= p_max_palabras) THEN EXIT; END IF;

                    END LOOP; -- Fin bucle símbolos
                    IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) THEN EXIT; END IF;
                END LOOP; -- Fin bucle años
                IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) THEN EXIT; END IF;
            END LOOP; -- Fin bucle profundidad
            IF (v_max_por_kw > 0 AND v_total_kw >= v_max_por_kw) THEN EXIT; END IF;
        END LOOP; -- Fin bucle case
    END LOOP; -- Fin bucle keywords

    -- [3] CIERRE Y SALIDA ALEATORIA
    -- Si p_shuffle es true, ejecutamos el desorden final mediante random()
    IF p_shuffle THEN
        RETURN QUERY SELECT val FROM tt_shuffle_pentest ORDER BY random();
    END IF;

    -- Si no hay shuffle, el proceso terminó mediante RETURN NEXT en los bucles
    RETURN;
END;
$func$;



---------------- COMMENT ----------------
COMMENT ON FUNCTION security.fn_generar_diccionario_pentest(text[], boolean, int, int, int, int, boolean) IS
'MOTOR DE DICCIONARIOS PENTESTING - GUÍA RÁPIDA:
1. PROPÓSITO: Automatizar la creación de wordlists basadas en patrones de comportamiento humano.
2. NIVELES DE PROFUNDIDAD:
   - 1: Básico (Símbolos al final).
   - 2: Medio (Añade símbolos al inicio/prefijos).
   - 3: Agresivo (Permutaciones cíclicas completas).
3. FLUJO: Palabra Exacta -> Case (Caja) -> Leetspeak -> Combinatoria Especial.
4. SEGURIDAD: Uso de tablas UNLOGGED para evitar rastro en WAL y SECURITY INVOKER.
5. BALANCEO: Reparto equitativo del límite p_max_palabras entre todas las keywords semillas.';

-- Verificar la documentación en la base de datos
-- SELECT description FROM pg_description JOIN pg_proc ON pg_proc.oid = pg_description.objoid WHERE proname = 'fn_generar_diccionario_pentest';

