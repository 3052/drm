package widevine

import "41.neocities.org/protobuf"

// Policy defines the playback policies for the license.
type Policy struct {
   CanPlay                 bool
   CanPersist              bool
   CanRenew                bool
   RentalDurationSeconds   int64
   PlaybackDurationSeconds int64
   LicenseDurationSeconds  int64
   RenewalDelaySeconds     int64
}

// ParsePolicy populates the struct from a protobuf message.
func (p *Policy) ParsePolicy(msg protobuf.Message) error {
   for _, field := range msg {
      switch field.Tag.FieldNum {
      case 1:
         p.CanPlay = field.Numeric == 1
      case 2:
         p.CanPersist = field.Numeric == 1
      case 3:
         p.CanRenew = field.Numeric == 1
      case 4:
         p.RentalDurationSeconds = int64(field.Numeric)
      case 5:
         p.PlaybackDurationSeconds = int64(field.Numeric)
      case 6:
         p.LicenseDurationSeconds = int64(field.Numeric)
      case 7:
         p.RenewalDelaySeconds = int64(field.Numeric)
      }
   }
   return nil
}
