import json
import zipfile
import io
from flask import Flask, request, render_template, send_file, make_response
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Load default information from info.json
with open('info.json', 'r') as f:
    default_info = json.load(f)


@app.route('/')
def index():
    config_cookie = request.cookies.get('config')
    if config_cookie:
        config = json.loads(config_cookie)
        return make_response(render_template('index.html',
                                             suffix=config['suffix'],
                                             country=config['country'],
                                             state=config['state'],
                                             locality=config['locality'],
                                             organization=config['organization'],
                                             organizational_unit=config['organizational_unit'],
                                             disable_suffix=config['disable_suffix']))
    else:
        config = default_info
        return render_template('index.html',
                               suffix=default_info['suffix'],
                               country=default_info['C'],
                               state=default_info['ST'],
                               locality=default_info['L'],
                               organization=default_info['O'],
                               organizational_unit=default_info['OU'],
                               disable_suffix=False)


@app.route('/generate_csr', methods=['POST'])
def generate_csr():
    domain_names = request.form['domain_names'].split(',')

    # Create a copy of default_info and update it with form data
    info = default_info.copy()

    info.update({
        "C": request.form.get('country', default_info['C']),
        "ST": request.form.get('state', default_info['ST']),
        "L": request.form.get('locality', default_info['L']),
        "O": request.form.get('organization', default_info['O']),
        "OU": request.form.get('organizational_unit', default_info['OU']),
        "suffix": request.form.get('suffix', default_info['suffix'])
    })

    # Check if the suffix field is disabled
    if request.form.get('disable_suffix'):
        info["suffix"] = ""

    # Ensure the country code is exactly 2 characters long
    if len(info['C']) != 2:
        return "Country code must be exactly 2 characters long", 400

    if info["suffix"]:
        domain_names = [f'{domain.strip()}.{info["suffix"]}' for domain in domain_names]

    # Create a key pair
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Export the private key to a file
    key_file = f'{domain_names[0].strip()}.key'
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Create a CSR with multiple domain names
    csr_builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, info['C']),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, info['ST']),
        x509.NameAttribute(NameOID.LOCALITY_NAME, info['L']),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, info['O']),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, info['OU']),
        x509.NameAttribute(NameOID.COMMON_NAME, domain_names[0].strip()),  # Use the first domain as the common name
    ]))

    # Add Subject Alternative Name (SAN) extension
    alt_names = [x509.DNSName(domain.strip()) for domain in domain_names]
    csr_builder = csr_builder.add_extension(
        x509.SubjectAlternativeName(alt_names),
        critical=False
    )

    csr = csr_builder.sign(key, hashes.SHA256())

    # Save the CSR to a file
    csr_file = f'{domain_names[0].strip()}.csr'
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    # Create a zip file in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr(key_file, key_pem)
        zip_file.writestr(csr_file, csr_pem)

    zip_buffer.seek(0)

    download_name = f'{domain_names[0].strip()}.zip'
    return send_file(zip_buffer, as_attachment=True, download_name=download_name, mimetype='application/zip')


if __name__ == '__main__':
    app.run(debug=True)