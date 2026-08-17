"use strict";

/**
 * Yeni oyunların SADECE oyun mantığına ait sunucu adaptörleri burada kaydedilir.
 * Masa, hak, turnuva, 100 kişilik, reconnect, görev, skor, bot profili ve matchmaking
 * server.js içindeki ortak altyapıyı kullanır.
 *
 * Örnek:
 * module.exports = ({ registerGameRuleAdapter }) => {
 *   registerGameRuleAdapter("equal_sum", {
 *     generatePuzzle: ({ difficulty, stage, mode }) => ({ ... }),
 *     validateAnswer: ({ puzzle, payload, mode }) => trueOrFalse,
 *   });
 * };
 */
module.exports = function installExtraGameRules(_api) {
  // Hedef Sayıyı Bul adaptörü geriye uyumluluk için server.js içinde kayıtlıdır.
  // Yeni oyunların yalnızca üretim/doğrulama mantığını buraya ekleyin.
};
