#!/usr/bin/env python3
"""Регресійні тести контролю доступу OWASP Juice Shop (варіант 26).

Кожен тест ПОВТОРЮЄ реальний експлойт (той самий HTTP-обмін, що й PoC) і
перевіряє НАСЛІДОК атаки, а не лише код статусу:
  - читання чужих даних не повертає їх;
  - запис у чужий ресурс не зберігається;
  - обхід ліміту більше не працює.

Запуск (сервер із виправленнями має бути піднятий на 127.0.0.1:3000):
    python3 -m pytest tests/ -v        # або
    python3 tests/test_access_control.py

Проти НЕвиправленого baseline ті самі перевірки падають (експлойт успішний) —
саме це доводить, що тест дійсно відтворює атаку.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "exploits"))

import poc1_basket_idor
import poc2_product_tamper
import poc3_ratelimit_xff_bypass
import poc4_user_enumeration
import poc5_forged_review
import poc6_basketitem_cross
import poc7_review_edit_idor


class AccessControlRegression(unittest.TestCase):
    """Після виправлень КОЖЕН експлойт має бути заблокований (success == False)."""

    def _assert_blocked(self, module):
        success, evidence, _ = module.exploit()
        self.assertFalse(success, f"Експлойт ВСЕ ЩЕ ПРАЦЮЄ: {evidence}")

    def test_r01_basket_idor_blocked(self):
        self._assert_blocked(poc1_basket_idor)

    def test_r02_product_tamper_blocked(self):
        self._assert_blocked(poc2_product_tamper)

    def test_r03_ratelimit_xff_bypass_blocked(self):
        self._assert_blocked(poc3_ratelimit_xff_bypass)

    def test_r04_user_enumeration_blocked(self):
        self._assert_blocked(poc4_user_enumeration)

    def test_r05_forged_review_blocked(self):
        self._assert_blocked(poc5_forged_review)

    def test_r06_basketitem_cross_blocked(self):
        self._assert_blocked(poc6_basketitem_cross)

    def test_r07_review_edit_idor_blocked(self):
        self._assert_blocked(poc7_review_edit_idor)


if __name__ == "__main__":
    unittest.main(verbosity=2)
