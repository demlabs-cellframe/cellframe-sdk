
class Test
   {
   public:

      /*
      * Some number of test results, all associated with who()
      */
      class Result final
         {
         public:
            explicit Result(const std::string& who) : m_who(who) {}

            size_t tests_passed() const
               {
               return m_tests_passed;
               }
            size_t tests_failed() const
               {
               return m_fail_log.size();
               }
            size_t tests_run() const
               {
               return tests_passed() + tests_failed();
               }
            bool any_results() const
               {
               return tests_run() > 0;
               }

            const std::string& who() const
               {
               return m_who;
               }

            std::string result_string() const;

            static Result Failure(const std::string& who,
                                  const std::string& what)
               {
               Result r(who);
               r.test_failure(what);
               return r;
               }

            static Result Note(const std::string& who,
                               const std::string& what)
               {
               Result r(who);
               r.test_note(what);
               return r;
               }

            static Result OfExpectedFailure(bool expecting_failure,
                                            const Test::Result& result)
               {
               if(!expecting_failure)
                  {
                  return result;
                  }

               if(result.tests_failed() == 0)
                  {
                  Result r = result;
                  r.test_failure("Expected this test to fail, but it did not");
                  return r;
                  }
               else
                  {
                  Result r(result.who());
                  r.test_note("Got expected failure");
                  return r;
                  }
               }

            void merge(const Result& other);

            void test_note(const std::string& note, const char* extra = nullptr);

            template<typename Alloc>
            void test_note(const std::string& who, const std::vector<uint8_t, Alloc>& vec)
               {
               const std::string hex = Botan::hex_encode(vec);
               return test_note(who, hex.c_str());
               }

            void note_missing(const std::string& thing);

            bool test_success(const std::string& note = "");

            bool test_failure(const std::string& err);

            bool test_failure(const std::string& what, const std::string& error);

            void test_failure(const std::string& what, const uint8_t buf[], size_t buf_len);

            template<typename Alloc>
            void test_failure(const std::string& what, const std::vector<uint8_t, Alloc>& buf)
               {
               test_failure(what, buf.data(), buf.size());
               }

            bool confirm(const std::string& what, bool expr, bool expected = true)
               {
               return test_eq(what, expr, expected);
               }

            template<typename T>
            bool test_is_eq(const T& produced, const T& expected)
               {
               return test_is_eq("comparison", produced, expected);
               }

            template<typename T>
            bool test_is_eq(const std::string& what, const T& produced, const T& expected)
               {
               std::ostringstream out;
               out << m_who << " " << what;

               if(produced == expected)
                  {
                  out << " produced expected result";
                  return test_success(out.str());
                  }
               else
                  {
                  out << " produced unexpected result '" << produced << "' expected '" << expected << "'";
                  return test_failure(out.str());
                  }
               }

            template<typename T>
            bool test_not_null(const std::string& what, T* ptr)
               {
               if(ptr == nullptr)
                  return test_failure(what + " was null");
               else
                  return test_success(what + " was not null");
               }

            template<typename T>
            bool test_not_nullopt(const std::string& what, std::optional<T> val)
               {
               if(val == std::nullopt)
                  return test_failure(what + " was nullopt");
               else
                  return test_success(what + " was not nullopt");
               }

            bool test_eq(const std::string& what, const char* produced, const char* expected);

            bool test_is_nonempty(const std::string& what_is_it, const std::string& to_examine);

