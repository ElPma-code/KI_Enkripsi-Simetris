Tugas 1 (kelompok beranggotakan empat orang)
Rancang dan bangun sebuah aplikasi web untuk skenario spesifik yang Anda pilih sendiri.

Pilih situasi dunia nyata yang konkret di mana perlindungan data pengguna yang tersimpan itu penting. Tentukan siapa penggunanya, apa yang mereka simpan, dan mengapa data tersebut perlu dilindungi.
"Layanan enkripsi file" yang generik bukan sebuah skenario dan tidak akan diterima. Aplikasi Anda harus jelas masuk akal untuk situasi yang Anda pilih.
Aplikasi Anda harus dapat menangani data pribadi, pindaian dokumen identitas, dokumen perkantoran, dan video.
Tentukan data apa yang termasuk data privat, dan dasarkan keputusan tersebut pada peraturan perlindungan data yang relevan (GDPR / UU PDP).
Semua data yang disimpan harus dilindungi dengan masing-masing cipher berikut: AES, DES, RC4.
Hanya pengguna yang terautentikasi yang boleh mengambil kembali datanya sendiri, dan data harus kembali utuh.
Persyaratan teknis
Pilih mode operasi yang sesuai untuk setiap block cipher. ECB tidak diperbolehkan.
Anda boleh menggunakan bahasa pemrograman dan library kriptografi apa pun.
Evaluasi perbandingan ketiga cipher tersebut dalam praktik. Tentukan apa yang diukur, bagaimana mengukurnya secara andal, dan apa arti hasilnya untuk skenario Anda. Jangan hanya menyajikan angka tanpa interpretasi.
Laporan (maksimal 2 halaman A4)
Skenario Anda, dan mengapa aplikasi ini berguna di dalamnya.
Analisis yang Anda pilih untuk dilakukan, dan mengapa analisis tersebut tepat untuk skenario Anda.
Justifikasi untuk setiap keputusan desain yang signifikan (arsitektur, pilihan mode operasi, pengelolaan kunci, penyimpanan, dll.). "Karena itu yang paling mudah" bukan justifikasi.
Pengumpulan dan penilaian
Push seluruh kode ke GitHub. Riwayat commit Anda akan digunakan untuk penilaian, jadi lakukan commit secara rutin dan bermakna.
Bagikan percakapan Anda dengan AI: sertakan tautan percakapan dan tangkapan layarnya dalam pengumpulan tugas. Jika Anda menggunakan AI, kami perlu melihat bagaimana Anda menggunakannya.
Nilai diberikan berdasarkan kebenaran program dan kualitas penalaran Anda.
Plagiarisme, termasuk konten hasil AI yang tidak diverifikasi, akan mendapat nilai 0.

Link percakapan AI :
https://chatgpt.com/share/6adf4f29-a0d0-83ec-a088-f1e2424d2933
https://claude.ai/share/aab5100f-e7da-42d0-976b-75a0e558edaf
https://chatgpt.com/share/6adf5e38-a864-83ec-a5b7-f73606255a94
https://chat.deepseek.com/share/202tuuge3ba10oj6h4

Tugas 2
Kembangkan aplikasi web Tugas 1 Anda, dengan tetap menggunakan skenario yang sama, agar pengguna dapat berbagi data privat mereka satu sama lain.

Seorang pengguna dapat meminta untuk melihat data privat pengguna lain, termasuk gambar dan dokumen.
Pengguna yang menerima permintaan membangkitkan sebuah kunci simetris untuk membagikan data kepada pengguna yang meminta.
Kunci simetris dikirimkan kepada pengguna yang meminta melalui cara lain (misalnya email, WhatsApp), di luar aplikasi Anda. Kunci tersebut harus dilindungi dengan enkripsi asimetris selama pengiriman.
Kunci simetris harus disimpan secara aman di dalam sistem Anda.
Persyaratan teknis
Anda boleh menggunakan bahasa pemrograman dan library kriptografi apa pun.
Tentukan sendiri bagaimana mekanisme berbagi data bekerja pada aplikasi dan skenario Anda. Setiap pilihan harus dijustifikasi.
Laporan (terpisah dari Tugas 1, maksimal 2 halaman A4)
Mengapa berbagi data dibutuhkan dalam skenario Anda, dan bagaimana pengguna akan memanfaatkannya.
Justifikasi untuk setiap keputusan desain yang signifikan pada fitur-fitur baru.
Analisis terhadap desain Anda. Sebagai titik awal, pikirkan apa saja yang dapat salah ketika data dibagikan antar pengguna, dan apakah desain Anda tetap aman. Tentukan apa yang akan dianalisis dan mengapa analisis tersebut tepat untuk skenario Anda.
Pengumpulan dan penilaian
Push seluruh kode ke GitHub. Riwayat commit Anda akan digunakan untuk penilaian, jadi lakukan commit secara rutin dan bermakna.
Bagikan percakapan Anda dengan AI: sertakan tautan percakapan dan tangkapan layarnya dalam pengumpulan tugas. Jika Anda menggunakan AI, kami perlu melihat bagaimana Anda menggunakannya.
Nilai diberikan berdasarkan kebenaran program dan kualitas penalaran Anda.
Plagiarisme, termasuk konten hasil AI yang tidak diverifikasi, akan mendapat nilai 0.

Link percakapan AI : 
https://chatgpt.com/share/6afb0f28-4c2c-83ec-a3b1-f69ac318c4ad
https://claude.ai/share/f87b9f38-e2b9-4346-b9f8-a8139b01f095

Tugas 3
Kembangkan aplikasi web dari tugas-tugas sebelumnya, dengan tetap menggunakan skenario yang sama, agar dokumen PDF yang diunggah dapat ditandatangani secara digital.

Dokumen PDF dapat ditandatangani menggunakan kunci privat pemiliknya.
Aplikasi Anda harus dapat memverifikasi tanda tangan tersebut.
Tanda tangan harus disematkan (embedded) di dalam PDF.
Jika pengguna belum memiliki pasangan kunci, aplikasi Anda harus dapat membangkitkannya.
Nilai tambahan jika tanda tangan dapat diverifikasi oleh pembaca PDF pihak ketiga.
Persyaratan teknis
Anda boleh menggunakan library untuk: membangkitkan pasangan kunci, menghitung nilai hash, dan enkripsi/dekripsi.
Anda boleh menggunakan library untuk membaca dan menulis file PDF. Logika penandatanganan dan verifikasi harus buatan Anda sendiri.
Setiap keputusan desain harus dijustifikasi.
Laporan (terpisah dari tugas-tugas sebelumnya, maksimal 2 halaman A4)
Mengapa tanda tangan digital dibutuhkan dalam skenario Anda, serta siapa yang menandatangani dan memverifikasi apa.
Justifikasi untuk setiap keputusan desain yang signifikan pada fitur-fitur baru.
Analisis terhadap desain Anda. Sebagai titik awal, pikirkan apa saja yang dapat salah ketika dokumen ditandatangani dan diverifikasi, dan apakah desain Anda tetap aman. Tentukan apa yang akan dianalisis dan mengapa analisis tersebut tepat untuk skenario Anda.
Pengumpulan dan penilaian
Push seluruh kode ke GitHub. Riwayat commit Anda akan digunakan untuk penilaian, jadi lakukan commit secara rutin dan bermakna.
Bagikan percakapan Anda dengan AI: sertakan tautan percakapan dan tangkapan layarnya dalam pengumpulan tugas. Jika Anda menggunakan AI, kami perlu melihat bagaimana Anda menggunakannya.
Nilai diberikan berdasarkan kebenaran program dan kualitas penalaran Anda.
Plagiarisme, termasuk konten hasil AI yang tidak diverifikasi, akan mendapat nilai 0.

Link Chat AI: 