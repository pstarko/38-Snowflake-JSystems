/*
Przykład: dział HR widzi pensje, reszta firmy — nie

Scenariusz: tabela employees z kolumną salary i pesel. Ma ją czytać cała firma (do raportów, listy pracowników), 
ale dane wrażliwe mają widzieć tylko role HR.

1. Struktura i role
*/

-- Tabela
CREATE OR REPLACE TABLE employees (
    employee_id NUMBER,
    full_name   VARCHAR,
    department  VARCHAR,
    email       VARCHAR,
    pesel       VARCHAR,
    salary      NUMBER(10,2)
);

-- Role
CREATE ROLE IF NOT EXISTS role_hr;
CREATE ROLE IF NOT EXISTS role_employee_general;

GRANT ROLE role_hr TO USER anna_hr;
GRANT ROLE role_employee_general TO USER jan_sprzedaz;

-- Dostęp do samej tabeli mają obie role (maskowanie zrobi resztę)
GRANT USAGE ON DATABASE hr_db TO ROLE role_hr, ROLE role_employee_general;
GRANT USAGE ON SCHEMA hr_db.public TO ROLE role_hr, ROLE role_employee_general;
GRANT SELECT ON TABLE employees TO ROLE role_hr, ROLE role_employee_general;

--2. Masking policy na salary i pesel
-- Pensja: HR widzi wartość, reszta widzi NULL
CREATE OR REPLACE MASKING POLICY mp_salary AS (val NUMBER) RETURNS NUMBER ->
  CASE
    WHEN CURRENT_ROLE() IN ('ROLE_HR', 'ACCOUNTADMIN') THEN val
    ELSE NULL
  END;

-- PESEL: HR widzi pełny, reszta widzi zamaskowany
CREATE OR REPLACE MASKING POLICY mp_pesel AS (val VARCHAR) RETURNS VARCHAR ->
  CASE
    WHEN CURRENT_ROLE() IN ('ROLE_HR', 'ACCOUNTADMIN') THEN val
    ELSE 'XXXXXXXXXXX'
  END;

-- Podpięcie polityk do kolumn
ALTER TABLE employees MODIFY COLUMN salary SET MASKING POLICY mp_salary;
ALTER TABLE employees MODIFY COLUMN pesel  SET MASKING POLICY mp_pesel;


--Efekt: to samo zapytanie, dwa różne wyniki — bez zmiany kodu aplikacji ani zapytań.

-- jako ROLE_HR
SELECT full_name, department, salary FROM employees;
-- Anna Nowak | HR       | 8500.00
-- Piotr Kowal| Sprzedaż | 6200.00

-- jako ROLE_EMPLOYEE_GENERAL
SELECT full_name, department, salary FROM employees;
-- Anna Nowak | HR       | NULL
-- Piotr Kowal| Sprzedaż | NULL


/*
3. Skalowanie: tag-based masking

	Ręczne podpinanie polityki do każdej kolumny w każdej tabeli szybko się nie skaluje. 
	Lepiej oznaczyć kolumny tagiem PII_SALARY/PII_ID raz — i podpiąć politykę do tagu. 
	Wtedy każda nowa tabela z taką kolumną automatycznie dziedziczy ochronę.
*/
CREATE OR REPLACE TAG tag_pii_salary;
CREATE OR REPLACE TAG tag_pii_id;

ALTER TAG tag_pii_salary SET MASKING POLICY mp_salary;
ALTER TAG tag_pii_id     SET MASKING POLICY mp_pesel;

-- Oznaczenie kolumn tagami (zamiast bezpośredniego SET MASKING POLICY)
ALTER TABLE employees MODIFY COLUMN salary SET TAG tag_pii_salary = 'salary';
ALTER TABLE employees MODIFY COLUMN pesel  SET TAG tag_pii_id = 'national_id';

/*
4. Dodatkowo: ograniczenie wierszy (Row Access Policy)

	Załóżmy, że kierownik działu ma widzieć pensje tylko swojego zespołu, nie całej firmy. 
	To już nie jest maskowanie kolumny, tylko filtrowanie wierszy.
*/

CREATE OR REPLACE TABLE dept_managers (
    manager_user VARCHAR,
    department   VARCHAR
);
INSERT INTO dept_managers VALUES ('piotr_kierownik', 'Sprzedaż');

CREATE OR REPLACE ROW ACCESS POLICY rap_own_department AS (dept VARCHAR)
RETURNS BOOLEAN ->
  CURRENT_ROLE() IN ('ROLE_HR', 'ACCOUNTADMIN')
  OR dept IN (
      SELECT department FROM dept_managers 
      WHERE manager_user = CURRENT_USER()
  );

ALTER TABLE employees ADD ROW ACCESS POLICY rap_own_department ON (department);

/*
Efekt: kierownik sprzedaży w SELECT * FROM employees zobaczy tylko wiersze z department = 'Sprzedaż' 
(a i tak z salary = NULL, bo maskowanie działa niezależnie i równolegle).
*/

/*
5. Zabezpieczenie przez widok (opcjonalnie, dodatkowa warstwa)
	Jeśli nie chcesz, żeby ktokolwiek w ogóle dotykał surowej tabeli — nadajesz SELECT tylko na secure view, a nie na tabelę bazową:
*/
CREATE OR REPLACE SECURE VIEW v_employees AS
SELECT employee_id, full_name, department, email, pesel, salary
FROM employees;

-- Odbierz dostęp bezpośredni do tabeli
REVOKE SELECT ON TABLE employees FROM ROLE role_employee_general;
GRANT SELECT ON VIEW v_employees TO ROLE role_employee_general;

/*
	Maskowanie i row access policy nadal działają, bo są podpięte na poziomie tabeli bazowej — widok je dziedziczy. 
	SECURE dodatkowo ukrywa definicję widoku (żeby ktoś nie odczytał logiki filtrowania przez SHOW VIEWS/GET_DDL).
*/

/*
6. Kto może to wszystko skonfigurować

Same polityki maskowania i tworzenie/podpinanie wymaga osobnego uprawnienia 
— zwykle nadaje się je dedykowanej roli bezpieczeństwa, nie każdemu administratorowi:

To rozdziela role: administrator danych zarządza tabelami, a osobna rola (security/compliance) decyduje, kto co widzi — 
co samo w sobie jest dobrą praktyką bezpieczeństwa (separacja obowiązków).
*/

GRANT CREATE MASKING POLICY ON SCHEMA hr_db.public TO ROLE security_admin;
GRANT APPLY MASKING POLICY ON ACCOUNT TO ROLE security_admin;
GRANT CREATE ROW ACCESS POLICY ON SCHEMA hr_db.public TO ROLE security_admin;
GRANT APPLY ROW ACCESS POLICY ON ACCOUNT TO ROLE security_admin;
