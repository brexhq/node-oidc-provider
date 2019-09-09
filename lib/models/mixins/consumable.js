module.exports = provider => superclass => class extends superclass {
  static get IN_PAYLOAD() {
    return [
      ...super.IN_PAYLOAD,
      'consumed',
      'consumedCount',
    ];
  }

  consume() {
    provider.emit('token.consumed', this);
    if (!this.consumed) {
      return this.adapter.consume(this.jti);
    } else {
      this.consumedCount = 1 + (this.consumedCount || 1);
      return this.save();
    }
  }

  get isValid() {
    return !this.consumed && !this.isExpired;
  }
};
